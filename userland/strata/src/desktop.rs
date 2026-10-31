// SPDX-License-Identifier: MIT OR Apache-2.0

//! The whole desktop for a window manager state: wallpaper, the shown
//! windows' frames and contents in stacking order, the panel. It draws
//! only within the canvas's clip (ADR 0038's damage): the wallpaper is
//! copied from a canvas drawn once, and windows the clip misses are
//! skipped.

use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;
use slate_ui::wallpaper::Design;
use slate_ui::{Canvas, Rect};

use crate::draw::{self, Bar, Frame, PanelHits, PanelWindow, TitleButton};
use crate::fonts::Fonts;
use crate::motion::Look;
use crate::wm::{State, WinId, Wm};

/// The top bar's live facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The day and time ("Mon 19 Oct  14:32").
    pub clock: String,
    /// The time alone and the date in words, for themes that show the
    /// date apart (ADR 0167): "14:32", "Wednesday 28 October".
    pub time: String,
    pub date: String,
    pub network: Option<bool>,
    pub battery: Option<u8>,
    /// Updates the last check found (the Software Updater's count).
    pub updates: usize,
    /// The volume in percent and whether it is muted; None without a
    /// sound card (ADR 0186).
    pub volume: Option<(u32, bool)>,
}

/// How far a window's shadow reaches beyond its frame.
pub const SHADOW_REACH: f32 = 80.0;

/// Where a window's frame is seen: at `seen` (its glide, or its place),
/// scaled by `scale` about its middle and shifted down `dy` (ADR 0186).
pub fn mapped(seen: Area, scale: f32, dy: f32) -> Area {
    let (w, h) = (seen.w * scale, seen.h * scale);
    Area::new(seen.x + (seen.w - w) / 2.0, seen.y + (seen.h - h) / 2.0 + dy, w, h)
}

/// Whether two areas overlap.
pub fn overlaps(a: &Area, b: &Area) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

/// The person's wallpaper: their picture covering the screen when they
/// chose one (and it reads), else the design.
pub fn wallpaper_for(pal: &Palette, s: &crate::settings::Settings, width: i32, height: i32, scale: f32) -> Canvas {
    if s.picture
        && let Some(img) = crate::faces::wallpaper()
    {
        let im = crate::faces::cover(&img, width.max(1) as u32, height.max(1) as u32);
        let mut c = Canvas::new(width, height, pal.desktop);
        // Opaque, whatever the picture's alpha.
        for (d, s) in c.pixels.iter_mut().zip(im.pixels.iter()) {
            *d = 0xFF00_0000 | (s & 0x00FF_FFFF);
        }
        return c;
    }
    wallpaper_canvas(pal, s.wallpaper, width, height, scale)
}

/// The wallpaper across several displays (ADR 0170): each display's own,
/// at its size, where it is in the screen (`rects`, device pixels); one
/// display's is [`wallpaper_for`]'s.
pub fn wallpapers(
    pal: &Palette,
    s: &crate::settings::Settings,
    rects: &[(i32, i32, i32, i32)],
    width: i32,
    height: i32,
    scale: f32,
) -> Canvas {
    if let [(0, 0, w, h)] = rects
        && (*w, *h) == (width, height)
    {
        return wallpaper_for(pal, s, width, height, scale);
    }
    let mut c = Canvas::new(width, height, pal.desktop);
    for &(x, y, w, h) in rects {
        let one = wallpaper_for(pal, s, w, h, scale);
        copy_rect_at(&mut c, &one, x, y);
    }
    c
}

/// `from` whole into `to` at (x, y).
fn copy_rect_at(to: &mut Canvas, from: &Canvas, x: i32, y: i32) {
    let r = Rect::new(x, y, from.width, from.height).intersect(&to.bounds());
    for row in r.y..r.bottom() {
        let src = ((row - y) * from.width + (r.x - x)) as usize;
        let dst = (row * to.width + r.x) as usize;
        to.pixels[dst..dst + r.w as usize].copy_from_slice(&from.pixels[src..src + r.w as usize]);
    }
}

/// The wallpaper, drawn once into its own canvas.
pub fn wallpaper_canvas(pal: &Palette, design: Design, width: i32, height: i32, scale: f32) -> Canvas {
    let mut c = Canvas::new(width, height, pal.desktop);
    let mut cache = slate_ui::text::GlyphCache::new();
    let mut p = Painter::new(&mut c, &mut cache, scale);
    let (w, h) = p.size();
    slate_ui::wallpaper::draw(&mut p, pal, Area::new(0.0, 0.0, w, h), design);
    c
}

/// The square of device pixels at a content area's bottom corners, as they
/// were before the content was drawn: (x, y, side, pixels) for each.
type Corners = [(i32, i32, i32, Vec<u32>); 2];

/// Save the bottom corners of content area `c` (device pixels), `r` the
/// radius.
fn save_corners(canvas: &Canvas, c: Rect, r: i32) -> Corners {
    let take = |x0: i32, y0: i32| {
        let mut px = Vec::with_capacity((r * r) as usize);
        for y in y0..y0 + r {
            for x in x0..x0 + r {
                let inside = x >= 0 && y >= 0 && x < canvas.width && y < canvas.height;
                px.push(if inside { canvas.pixels[(y * canvas.width + x) as usize] } else { 0 });
            }
        }
        (x0, y0, r, px)
    };
    [take(c.x, c.bottom() - r), take(c.right() - r, c.bottom() - r)]
}

/// Put back, outside the rounded corner, what [`save_corners`] saved,
/// blending along the arc (the frame's radius, ADR 0039).
fn mask_corners(canvas: &mut Canvas, corners: &Corners, left_x: i32) {
    for (x0, y0, r, saved) in corners {
        let left = *x0 == left_x;
        // The arc's centre: inside the square, at the far side from the
        // corner.
        let (cx, cy) = (if left { (x0 + r) as f32 } else { *x0 as f32 }, *y0 as f32);
        for dy in 0..*r {
            for dx in 0..*r {
                let (x, y) = (x0 + dx, y0 + dy);
                if x < 0 || y < 0 || x >= canvas.width || y >= canvas.height || !canvas.clip().contains(x, y) {
                    continue;
                }
                let (fx, fy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                let d = slate_ui::math::sqrt(fx * fx + fy * fy);
                let cover = (*r as f32 - d + 0.5).clamp(0.0, 1.0);
                if cover >= 1.0 {
                    continue;
                }
                let i = (y * canvas.width + x) as usize;
                let (new, old) = (canvas.pixels[i], saved[(dy * r + dx) as usize]);
                let mix = |sh: u32| {
                    let (a, b) = (((new >> sh) & 0xFF) as f32, ((old >> sh) & 0xFF) as f32);
                    ((a * cover + b * (1.0 - cover)) as u32 & 0xFF) << sh
                };
                canvas.pixels[i] = 0xFF00_0000 | mix(16) | mix(8) | mix(0);
            }
        }
    }
}

/// Copy `r` of `from` (the same size as `to`) into `to`.
fn copy_rect(to: &mut Canvas, from: &Canvas, r: Rect) {
    let r = r.intersect(&to.bounds());
    for y in r.y..r.bottom() {
        let at = (y * to.width + r.x) as usize;
        let n = r.w as usize;
        to.pixels[at..at + n].copy_from_slice(&from.pixels[at..at + n]);
    }
}

/// What the desktop shows beyond the window manager's state.
#[derive(Clone, Copy, Default)]
pub struct Extras<'a> {
    /// The wallpaper drawn once, copied from (drawn anew when None).
    pub wall: Option<&'a Canvas>,
    /// The title bar button under the pointer, and how far its fill has
    /// faded in (fully when None).
    pub hover: Option<(WinId, TitleButton)>,
    pub hover_in: Option<f32>,
    /// The title bar button with the keyboard focus (alt + space).
    pub keyed: Option<(WinId, TitleButton)>,
    /// The Applications menu is open.
    pub menu: bool,
    /// The power dialog is open.
    pub power: bool,
    /// A restart or shut down set for later, as the top bar says it.
    pub pending: Option<&'a str>,
    /// How each window looks now (motion); all plain when None.
    pub look: Option<&'a dyn Fn(WinId) -> Look>,
    /// Where a window being dragged would snap to (ADR 0039).
    pub preview: Option<Area>,
    /// The first window the panel's list shows.
    pub list_first: usize,
    /// A workspace switch sliding (ADR 0039).
    pub slide: Option<crate::motion::Slide>,
    /// Unfocused windows' contents dimmed to 85% (§4, a setting).
    pub dim: bool,
    /// The live system (M27): the panel offers to install.
    pub live: bool,
    /// The desktop's icons (ADR 0102's third addendum), and whether
    /// they have the keys (no window focused; ADR 0156).
    pub desk: Option<&'a crate::desk::Desk>,
    pub desk_keys: bool,
    /// Files an app drags outside its window: where the pointer is, how
    /// many, and whether they are copied (ctrl held; the desktop's icons
    /// too).
    pub drag_badge: Option<(f32, f32, usize, bool)>,
    /// A window being resized: its size in steps is shown.
    pub resizing: Option<WinId>,
    /// Closed windows still fading (ADR 0186), drawn over the rest.
    pub ghosts: &'a [Ghost],
    /// How far the snap preview has faded in (1 when None).
    pub preview_in: Option<f32>,
    /// The size (logical) of what gliding windows' apps last drew.
    pub drawn_sizes: &'a [(WinId, (f32, f32))],
    /// The title bar button held down, and the top bar's control.
    pub pressed: Option<(WinId, TitleButton)>,
    pub bar_pressed: Option<Area>,
    /// An app being opened: its name and the spinner's step.
    pub opening: Option<(&'a str, u8)>,
    /// Quick settings are open (ADR 0186).
    pub quick: bool,
    /// The battery's percentage hidden from the top bar (a setting).
    pub hide_battery_percent: bool,
    /// The volume keys' pop-up and its opacity.
    pub osd: Option<(&'a crate::quick::Osd, f32)>,
    /// The notifications, for their banners and the top bar's mark, the
    /// time, and whether motion is reduced.
    pub notes: Option<(&'a crate::notes::Notes, i64, bool)>,
}

/// A closed window as it was: drawn, fading and shrinking, from its last
/// contents (which the session keeps) until its motion ends (ADR 0186).
#[derive(Clone, Debug)]
pub struct Ghost {
    pub win: crate::wm::Window,
    pub area: Area,
}

impl core::fmt::Debug for Extras<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Extras(hover {:?}, menu {})", self.hover, self.menu)
    }
}

/// Draw the desktop within the canvas's clip; `contents` draws a window's
/// content in its area. Returns where the panel's controls are.
pub fn desktop(
    p: &mut Painter<'_>,
    pal: &Palette,
    f: &Fonts<'_>,
    wm: &Wm,
    status: &Status,
    extras: Extras<'_>,
    contents: &mut dyn FnMut(&mut Painter<'_>, WinId, Area),
) -> PanelHits {
    let (w, h) = p.size();
    let clip = p.canvas.clip();
    let k = p.scale;
    let (ox, oy) = p.origin();
    let damage = Area::new(clip.x as f32 / k + ox, clip.y as f32 / k + oy, clip.w as f32 / k, clip.h as f32 / k);
    match extras.wall {
        Some(c) => copy_rect(p.canvas, c, clip),
        None => draw::wallpaper(p, pal, Area::new(0.0, 0.0, w, h)),
    }
    if let Some(d) = extras.desk {
        draw::desk_icons(p, pal, f, wm.work, d, extras.desk_keys);
    }
    let focused = wm.focused().map(|win| win.id);
    let mut layer: Option<Canvas> = None;
    // While sliding: the workspace left, a screen's width aside, then the
    // shown one, both shifted.
    let shown: Vec<(WinId, Area)> = match extras.slide {
        Some(mut s) => {
            // Whole device pixels: a shadow is kept by where it falls
            // within a pixel, and fractional steps would make each frame's
            // anew (at 4K, a third of a slide's frame; M32 phase 2).
            s.shift = slate_ui::math::round(s.shift * k) / k;
            let moved = |list: Vec<(WinId, Area)>, by: f32| -> Vec<(WinId, Area)> {
                list.into_iter().map(|(id, a)| (id, Area::new(a.x + by, a.y, a.w, a.h))).collect()
            };
            let mut v = moved(wm.layout_on(s.from), s.shift - s.dir * w);
            v.extend(moved(wm.layout(), s.shift));
            v
        }
        None => wm.layout(),
    };
    let mut drawn: Vec<(WinId, Area, &crate::wm::Window)> =
        shown.into_iter().filter_map(|(id, a)| wm.get(id).map(|w| (id, a, w))).collect();
    drawn.extend(extras.ghosts.iter().map(|g| (g.win.id, g.area, &g.win)));
    for (id, a, win) in drawn {
        let look = extras.look.map_or(Look::still(f32::from(u8::from(focused == Some(id)))), |l| l(id));
        // Where it is seen: gliding, or in its place.
        let seen = look.at.unwrap_or(a);
        if !overlaps(&seen.grow(SHADOW_REACH + look.dy.abs()), &damage) || look.opacity <= 0.0 {
            continue;
        }
        let flush = win.state.flush();
        let fr = Frame {
            app: &win.app,
            path: win.path.as_deref(),
            linux: win.linux,
            sandboxed: win.sandboxed,
            linux_box: win.linux_box.as_deref(),
            icon: win.icon,
            image: win.image.as_deref(),
            accent: win.accent,
            focus: look.focus,
            flush,
            maximized: win.state == State::Maximized,
            hover: extras.hover.filter(|h| h.0 == id).map(|h| h.1),
            hover_in: extras.hover_in.unwrap_or(1.0),
            keyed: extras.keyed.filter(|h| h.0 == id).map(|h| h.1),
            pressed: extras.pressed.filter(|h| h.0 == id).map(|h| h.1),
        };
        let mut draw_window = |p: &mut Painter<'_>, a: Area| {
            draw::frame(p, pal, f, a, &fr);
            let c = draw::content(a, pal.shape.title_h);
            // The content's bottom corners follow the frame's radius.
            let dev = p.device(&c);
            let r = ((pal.shape.frame_r - 1.0) * p.scale) as i32;
            let corners = (!flush).then(|| save_corners(p.canvas, dev, r));
            let saved = p.clip(c);
            contents(p, id, c);
            if extras.dim && look.focus < 1.0 {
                // 85% opacity over the window's own surface: 15% of it on
                // top, fading with the focus.
                p.fill(c, 0.0, pal.window.with_alpha((38.0 * (1.0 - look.focus)) as u8));
            }
            p.unclip(saved);
            if let Some(cs) = &corners {
                mask_corners(p.canvas, cs, dev.x);
            }
            draw::frame_outline(p, pal, a, look.focus, flush, win.accent);
        };
        if look.plain() {
            draw_window(p, a);
        } else if look.scale == 1.0 && look.at.is_none() {
            // A fading window: drawn into a transparent layer, then
            // composited at its opacity, shifted.
            let l =
                layer.get_or_insert_with(|| Canvas::new(p.canvas.width, p.canvas.height, slate_ui::Color::TRANSPARENT));
            l.clear();
            l.set_clip(clip);
            {
                let mut lp = Painter::new(l, &mut *p.cache, k);
                draw_window(&mut lp, a);
            }
            p.canvas.composite(l, look.opacity, (look.dy * k) as i32);
        } else {
            // Scaling or gliding (ADR 0186): drawn whole into the layer
            // in its place, then stretched onto where it is seen. A
            // gliding window is drawn at the size its app last drew, so
            // its contents keep their proportions until the new ones come.
            let c = draw::content(a, pal.shape.title_h);
            let a = match extras.drawn_sizes.iter().find(|(w, _)| *w == id) {
                Some(&(_, (cw, ch))) if look.at.is_some() && cw > 0.0 && ch > 0.0 => {
                    Area::new(a.x, a.y, cw + (a.w - c.w), ch + (a.h - c.h))
                }
                _ => a,
            };
            let l =
                layer.get_or_insert_with(|| Canvas::new(p.canvas.width, p.canvas.height, slate_ui::Color::TRANSPARENT));
            l.clear();
            let reach = if flush { 0.0 } else { SHADOW_REACH };
            let from = p.device(&a.grow(reach)).intersect(&l.bounds());
            l.set_clip(from);
            {
                let mut lp = Painter::new(l, &mut *p.cache, k).at((ox, oy), (w, h));
                draw_window(&mut lp, a);
            }
            let to = mapped(seen, look.scale, look.dy);
            // The layer's part `from`, mapped as the frame is.
            let (fx, fy) = ((from.x as f32) / k + ox, (from.y as f32) / k + oy);
            let (fw, fh) = (from.w as f32 / k, from.h as f32 / k);
            let sx = to.w / a.w;
            let sy = to.h / a.h;
            let dest = ((to.x + (fx - a.x) * sx - ox) * k, (to.y + (fy - a.y) * sy - oy) * k, fw * sx * k, fh * sy * k);
            p.canvas.composite_mapped(l, from, dest, look.opacity);
        }
    }
    if let Some(id) = extras.resizing
        && let (Some(a), Some(size)) = (wm.frame(id), wm.size_in_steps(id))
    {
        draw::step_size(p, pal, f, draw::content(a, pal.shape.title_h), size);
    }
    // Where a dragged window would snap.
    if let Some(a) = extras.preview {
        let a = a.grow(-8.0);
        let k = extras.preview_in.unwrap_or(1.0).clamp(0.0, 1.0);
        p.fill(a, 12.0, pal.chalk.with_alpha((18.0 * k) as u8));
        p.border(a, 12.0, 1.5, pal.focus.with_alpha((150.0 * k) as u8));
    }
    let windows: Vec<PanelWindow<'_>> = wm
        .listed(wm.active)
        .iter()
        .map(|win| PanelWindow {
            name: &win.app,
            focused: focused == Some(win.id),
            minimized: win.state == State::Minimized,
        })
        .collect();
    let b = Bar {
        workspaces: wm.workspaces(),
        windows: &windows,
        menu: extras.menu,
        power: extras.power,
        linux: wm.focused().is_some_and(|w| w.linux),
        sandboxed: wm.focused().is_some_and(|w| w.sandboxed),
        linux_box: wm.focused().and_then(|w| w.linux_box.as_deref()),
        network: status.network,
        battery: status.battery,
        updates: status.updates,
        pending: extras.pending,
        clock: if pal.topbar_date.alpha() > 0 && !status.date.is_empty() { &status.time } else { &status.clock },
        date: Some(status.date.as_str()).filter(|d| !d.is_empty()),
        first: extras.list_first,
        live: extras.live,
        pressed: extras.bar_pressed,
        opening: extras.opening,
        volume: status.volume,
        quick: extras.quick,
        unread: extras.notes.is_some_and(|(n, _, _)| n.unread()),
        hide_percent: extras.hide_battery_percent,
    };
    let mut hits = draw::bar(p, pal, f, &b);
    if let Some(d) = extras.desk {
        draw::desk_over(p, pal, f, wm.work, d);
    }
    if let Some((x, y, n, copy)) = extras.drag_badge {
        draw::drag_badge(p, pal, f, x, y, n, copy);
    }
    // Notifications' banners at the top right (ADR 0186).
    if let Some((notes, now, reduced)) = extras.notes {
        hits.banners = crate::notes::draw_banners(p, pal, f, notes, w, now, reduced);
    }
    // The volume and brightness keys' pop-up, over everything.
    if let Some((o, k)) = extras.osd {
        crate::quick::draw_osd(p, pal, f, o, k, w, h);
    }
    hits
}

/// The shortcuts, as the "keys" app lists them.
pub const SHORTCUTS: [(&str, &str); 12] = [
    ("super", "the Applications menu"),
    ("super + enter", "open a terminal"),
    ("super + space", "the launcher"),
    ("alt + tab", "the next window"),
    ("alt + space", "the window's buttons (arrows, enter)"),
    ("super + up / down", "maximise / minimise (from a half: its quarters)"),
    ("super + left / right", "the left or right half"),
    ("super + q", "close the focused window"),
    ("super + 1–4", "switch workspace (with shift: send there)"),
    ("super + l", "lock the screen"),
    ("super + s", "quick settings"),
    ("super + shift + e", "leave Strata"),
];

/// The "keys" app's content: what the shortcuts are.
pub fn keys_window(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, c: Area) {
    let mut y = c.y + 18.0;
    p.icon(Icon::Terminal, c.x + 20.0, y + 2.0, 16.0, pal.text_3);
    let title = p.style(&f.medium, 15.0, pal.chalk);
    p.line(&title, c.x + 46.0, y, 20.0, "Strata");
    y += 34.0;
    let (key, label) = (p.style(&f.mono, 12.5, pal.text_1), p.style(&f.mono, 12.5, pal.muted));
    for (k, l) in SHORTCUTS {
        p.line(&key, c.x + 20.0, y, 22.0, k);
        p.line(&label, c.x + 220.0, y, 22.0, l);
        y += 22.0;
    }
}
