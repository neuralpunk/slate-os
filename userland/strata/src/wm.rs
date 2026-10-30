// SPDX-License-Identifier: MIT OR Apache-2.0

//! The window manager's state (ADR 0038): floating windows on four
//! workspaces, in stacking order, each normal, maximised, snapped to a
//! half or a quarter (ADR 0102), or minimised; the sizes apps ask for; the focus on each workspace; where things are under
//! the pointer; and the commands keys give. No platform here: the session
//! drives it.

use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::icon::Icon;
use slate_ui::math::{ceil, floor, round};
use slate_ui::ui::Area;

use crate::draw::{self, Workspace};
use crate::layout::BAR_H;

pub type WinId = u32;

pub const WORKSPACES: usize = 4;
/// The smallest a window may be resized to.
pub const MIN_W: f32 = 240.0;
pub const MIN_H: f32 = 160.0;
/// The band around a frame that resizes it.
pub const GRIP: f32 = 6.0;
/// How far each new window is offset from the last.
const CASCADE: f32 = 24.0;

/// How a window is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Normal,
    Maximized,
    Left,
    Right,
    /// The quarters (ADR 0102).
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
    Minimized,
}

impl State {
    /// Snapped to part of the screen, or maximised: no radius or shadow.
    pub fn flush(self) -> bool {
        !matches!(self, State::Normal | State::Minimized)
    }
}

/// How far from a corner a drag snaps to a quarter.
const CORNER: f32 = 48.0;

/// A managed window.
#[derive(Clone, Debug, PartialEq)]
pub struct Window {
    pub id: WinId,
    pub app: String,
    pub path: Option<String>,
    /// Its program runs in the Linux domain.
    pub linux: bool,
    /// ... inside a Linux runtime's sandbox (slate-linux-app, ADR 0038).
    pub sandboxed: bool,
    /// ... in a Linux box, by the kernel's tag (ADR 0183): its name.
    pub linux_box: Option<String>,
    /// Its app's glyph, from the entry whose `exec` it runs (ADR 0124).
    pub icon: Option<Icon>,
    /// Its app's accent in Sediment, from the entry whose `exec` its
    /// program is, as the kernel names it (ADR 0167 and its addendum).
    pub accent: Option<slate_ui::themes::Stratum>,
    /// A Linux app's own icon, from its launcher entry (M31 phase 4).
    pub image: Option<alloc::rc::Rc<slate_image::Image>>,
    pub workspace: usize,
    /// The frame when normal.
    pub rect: Area,
    pub state: State,
    /// The state to restore from minimised.
    before: State,
    /// The smallest size its app takes (logical pixels; ADR 0102).
    pub min: (f32, f32),
    /// The person has resized it: the app's preferred size no longer
    /// applies.
    sized: bool,
    /// The steps its app resizes in (a terminal's cells), if any.
    pub steps: Option<Steps>,
}

/// Steps a window's content resizes in (ADR 0102's third addendum): a
/// base size and a whole number of steps (logical pixels, of the
/// content).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Steps {
    pub base: (f32, f32),
    pub step: (f32, f32),
}

/// The frame's width beyond its content (draw::content: the border; its
/// height adds the theme's title bar, [`Wm::extra_h`]).
const EXTRA_W: f32 = 2.0;

impl Steps {
    /// How many steps fit in a content length (one axis).
    fn count(len: f32, base: f32, step: f32) -> f32 {
        floor((len - base) / step + 0.01).max(0.0)
    }

    /// A frame length (one axis) brought down to a whole number of steps,
    /// and up again to `min`. Half a pixel more than the steps need, so
    /// the app's own rounding down finds all of them.
    fn fit(frame: f32, extra: f32, base: f32, step: f32, min: f32) -> f32 {
        if step < 1.0 {
            return frame;
        }
        let at = |k: f32| ceil(base + k * step + 0.5) + extra;
        let mut k = Steps::count(frame - extra, base, step);
        while at(k) < min && k < 10_000.0 {
            k += 1.0;
        }
        at(k)
    }

    /// The frame size `(w, h)` in whole steps, no smaller than `min`;
    /// `extra_h` is the frame's height beyond its content.
    pub fn frame(&self, (w, h): (f32, f32), min: (f32, f32), extra_h: f32) -> (f32, f32) {
        (
            Steps::fit(w, EXTRA_W, self.base.0, self.step.0, min.0),
            Steps::fit(h, extra_h, self.base.1, self.step.1, min.1),
        )
    }

    /// The steps in a frame of `(w, h)`: a terminal's columns and rows.
    pub fn of(&self, (w, h): (f32, f32), extra_h: f32) -> (u32, u32) {
        let n = |len: f32, base: f32, step: f32| if step < 1.0 { 0 } else { Steps::count(len, base, step) as u32 };
        (n(w - EXTRA_W, self.base.0, self.step.0), n(h - extra_h, self.base.1, self.step.1))
    }
}

/// Which edges a resize moves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Edges {
    pub left: bool,
    pub right: bool,
    pub top: bool,
    pub bottom: bool,
}

/// What is under the pointer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Hit {
    Close(WinId),
    Maximize(WinId),
    Minimize(WinId),
    Title(WinId),
    Edge(WinId, Edges),
    Content(WinId),
}

impl Edges {
    /// The pointer's shape over these edges.
    pub fn cursor(self) -> slate_ui::icon::Cursor {
        use slate_ui::icon::Cursor;
        let (h, v) = (self.left || self.right, self.top || self.bottom);
        match (h, v) {
            (true, false) => Cursor::ResizeH,
            (false, true) => Cursor::ResizeV,
            (true, true) if (self.left && self.top) || (self.right && self.bottom) => Cursor::ResizeNwse,
            (true, true) => Cursor::ResizeNesw,
            (false, false) => Cursor::Arrow,
        }
    }
}

impl Hit {
    pub fn window(self) -> WinId {
        match self {
            Hit::Close(id)
            | Hit::Maximize(id)
            | Hit::Minimize(id)
            | Hit::Title(id)
            | Hit::Edge(id, _)
            | Hit::Content(id) => id,
        }
    }
}

/// What a key binding asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// super + 1-4.
    Workspace(usize),
    /// super + shift + 1-4: the focused window to another workspace.
    MoveToWorkspace(usize),
    /// super + up: maximise, or restore; from a half, its top quarter.
    Maximize,
    /// super + down: minimise; from a half, its bottom quarter; from a
    /// quarter, back to its half.
    Minimize,
    /// super + left/right: the left or right half; from a quarter, the
    /// quarter beside it.
    SnapLeft,
    SnapRight,
    /// alt + tab: the next window.
    Cycle,
    /// super + q.
    Close,
    /// super + enter.
    Terminal,
    /// super + space.
    Launcher,
    /// super alone (pressed and released with nothing between): the
    /// Applications menu, or closing it.
    Applications,
    /// super + shift + e: leave Strata.
    Quit,
    /// super + L: the lock screen (ADR 0039).
    Lock,
    /// alt + space: the keyboard focus to the focused window's title bar
    /// buttons (ADR 0124's addendum).
    TitleButtons,
}

/// What a key does while a title bar's buttons have the keyboard focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleKey {
    /// The focus moves to this button.
    Focus(draw::TitleButton),
    /// The button is pressed, as a click would.
    Press(draw::TitleButton),
    /// Esc: the focus goes back to the app.
    Leave,
}

/// The key `code` with the focus on title bar button `at`: left and
/// right (tab and shift + tab) move along the three, round from one end
/// to the other; enter and space press; esc leaves. None for any other
/// key, which leaves the buttons and goes to the app.
pub fn title_key(at: draw::TitleButton, code: u16, shift: bool) -> Option<TitleKey> {
    use draw::TitleButton::{Close, Maximize, Minimize};
    use slate_display::input::*;
    let order = [Minimize, Maximize, Close];
    let i = order.iter().position(|b| *b == at).unwrap_or(0);
    Some(match code {
        KEY_LEFT => TitleKey::Focus(order[(i + 2) % 3]),
        KEY_TAB if shift => TitleKey::Focus(order[(i + 2) % 3]),
        KEY_RIGHT | KEY_TAB => TitleKey::Focus(order[(i + 1) % 3]),
        KEY_ENTER | KEY_KPENTER | KEY_SPACE => TitleKey::Press(at),
        KEY_ESC => TitleKey::Leave,
        _ => return None,
    })
}

/// The binding for a key press, if any (docs/design/WM_STYLE.md §10, ADR 0038).
pub fn binding(code: u16, logo: bool, shift: bool, alt: bool) -> Option<Command> {
    use slate_display::input::*;
    if alt && !logo && code == KEY_TAB {
        return Some(Command::Cycle);
    }
    if alt && !logo && code == KEY_SPACE {
        return Some(Command::TitleButtons);
    }
    // The input layer's lone logo key, at its release (the logo bit off).
    if matches!(code, KEY_LEFTMETA | KEY_RIGHTMETA) && !logo && !shift && !alt {
        return Some(Command::Applications);
    }
    if !logo {
        return None;
    }
    Some(match code {
        KEY_UP => Command::Maximize,
        KEY_DOWN => Command::Minimize,
        KEY_LEFT => Command::SnapLeft,
        KEY_RIGHT => Command::SnapRight,
        KEY_1..=KEY_4 if shift => Command::MoveToWorkspace((code - KEY_1) as usize),
        KEY_1..=KEY_4 => Command::Workspace((code - KEY_1) as usize),
        KEY_Q => Command::Close,
        KEY_ENTER => Command::Terminal,
        KEY_SPACE => Command::Launcher,
        KEY_E if shift => Command::Quit,
        KEY_L => Command::Lock,
        _ => return None,
    })
}

#[derive(Clone, Debug)]
pub struct Wm {
    /// Every window, bottom of the stack first.
    pub windows: Vec<Window>,
    pub active: usize,
    focus: [Option<WinId>; WORKSPACES],
    next: WinId,
    placed: u32,
    /// The screen below the panel, in logical pixels: the primary
    /// display's (its corner at (0, 0)).
    pub work: Area,
    /// The other displays, logical pixels (no panel on them; ADR 0170).
    pub others: Vec<Area>,
    /// The theme's title bar height, its groove included (ADR 0167).
    pub title_h: f32,
}

impl Wm {
    /// A window manager for a `w` × `h` (logical) screen.
    pub fn new(w: f32, h: f32) -> Wm {
        Wm {
            windows: Vec::new(),
            active: 0,
            focus: [None; WORKSPACES],
            next: 1,
            placed: 0,
            work: Area::new(0.0, BAR_H, w, h - BAR_H),
            others: Vec::new(),
            title_h: draw::TITLE_H,
        }
    }

    /// The displays changed: the primary is `w` × `h` with the panel
    /// `bar_h` high, the others where `others` says. Windows left on no
    /// display come back to the primary.
    pub fn set_screens(&mut self, w: f32, h: f32, bar_h: f32, others: Vec<Area>) {
        self.work = Area::new(0.0, bar_h, w, h - bar_h);
        self.others = others;
        let wk = self.work;
        for i in 0..self.windows.len() {
            let r = self.windows[i].rect;
            let (cx, cy) = (r.x + r.w / 2.0, r.y + r.h / 2.0);
            if !self.screens().any(|s| s.contains(cx, cy)) {
                let (nw, nh) = (r.w.min(wk.w), r.h.min(wk.h));
                self.windows[i].rect =
                    Area::new(round(wk.x + (wk.w - nw) / 2.0), round(wk.y + (wk.h - nh) / 2.0), nw, nh);
            }
        }
    }

    /// Every display's area (the primary's below the panel), the primary
    /// first.
    pub fn screens(&self) -> impl Iterator<Item = Area> + '_ {
        core::iter::once(self.work).chain(self.others.iter().copied())
    }

    /// The display (its area) that holds (x, y), or the nearest.
    pub fn screen_at(&self, x: f32, y: f32) -> Area {
        let dist = |a: &Area| {
            let dx = (a.x - x).max(x - a.right()).max(0.0);
            let dy = (a.y - y).max(y - a.bottom()).max(0.0);
            dx * dx + dy * dy
        };
        self.screens().min_by(|a, b| dist(a).total_cmp(&dist(b))).unwrap_or(self.work)
    }

    /// The display a frame is on: the one holding its middle.
    fn screen_of(&self, r: &Area) -> Area {
        self.screen_at(r.x + r.w / 2.0, r.y + r.h / 2.0)
    }

    /// Whether (x, y) is on the panel (the primary display's top).
    pub fn in_bar(&self, x: f32, y: f32) -> bool {
        (0.0..self.work.y).contains(&y) && x >= self.work.x && x < self.work.right()
    }

    /// The theme's title bar and top bar heights (ADR 0167): the work
    /// area starts under the top bar, and windows stay below it.
    pub fn shape(&mut self, title_h: f32, bar_h: f32) {
        let bottom = self.work.bottom();
        self.title_h = title_h;
        self.work = Area::new(self.work.x, bar_h, self.work.w, bottom - bar_h);
        for w in &mut self.windows {
            w.rect.y = w.rect.y.max(bar_h);
        }
    }

    /// A frame's height beyond its content: the title bar and the border.
    pub fn extra_h(&self) -> f32 {
        self.title_h + 1.0
    }

    /// A new window on the active workspace: centred at about 60% × 70%
    /// of the work area, cascading, on top and focused.
    pub fn add(&mut self, app: &str, path: Option<&str>, linux: bool) -> WinId {
        let id = self.next;
        self.next += 1;
        let wk = self.work;
        let (w, h) = (round(wk.w * 0.6).max(MIN_W.min(wk.w)), round(wk.h * 0.7).max(MIN_H.min(wk.h)));
        let step = (self.placed % 6) as f32 * CASCADE - 2.5 * CASCADE;
        self.placed += 1;
        let x = round(wk.x + (wk.w - w) / 2.0 + step).clamp(wk.x, wk.right() - w);
        let y = round(wk.y + (wk.h - h) / 2.0 + step).clamp(wk.y, wk.bottom() - h);
        self.windows.push(Window {
            id,
            app: String::from(app),
            path: path.map(String::from),
            linux,
            sandboxed: false,
            linux_box: None,
            icon: None,
            accent: None,
            image: None,
            workspace: self.active,
            rect: Area::new(x, y, w, h),
            state: State::Normal,
            before: State::Normal,
            min: (MIN_W, MIN_H),
            sized: false,
            steps: None,
        });
        self.focus[self.active] = Some(id);
        id
    }

    pub fn get(&self, id: WinId) -> Option<&Window> {
        self.windows.iter().find(|w| w.id == id)
    }

    pub fn get_mut(&mut self, id: WinId) -> Option<&mut Window> {
        self.windows.iter_mut().find(|w| w.id == id)
    }

    /// The topmost shown window on `ws` other than `except`.
    fn top_on(&self, ws: usize, except: Option<WinId>) -> Option<WinId> {
        self.windows
            .iter()
            .rev()
            .find(|w| w.workspace == ws && w.state != State::Minimized && Some(w.id) != except)
            .map(|w| w.id)
    }

    /// Remove a window; the focus goes to the window below it.
    pub fn remove(&mut self, id: WinId) {
        let Some(i) = self.windows.iter().position(|w| w.id == id) else { return };
        let ws = self.windows[i].workspace;
        self.windows.remove(i);
        if self.focus[ws] == Some(id) {
            self.focus[ws] = self.top_on(ws, None);
        }
    }

    /// The windows on workspace `ws`, bottom first (the window list's
    /// order is this too).
    pub fn on(&self, ws: usize) -> Vec<&Window> {
        self.windows.iter().filter(|w| w.workspace == ws).collect()
    }

    /// The windows on workspace `ws` in the order they opened: the
    /// panel's window list, which does not reorder as windows are raised.
    pub fn listed(&self, ws: usize) -> Vec<&Window> {
        let mut v = self.on(ws);
        v.sort_by_key(|w| w.id);
        v
    }

    /// The windows drawn on the active workspace, bottom first.
    pub fn visible(&self) -> Vec<&Window> {
        self.windows.iter().filter(|w| w.workspace == self.active && w.state != State::Minimized).collect()
    }

    pub fn focused(&self) -> Option<&Window> {
        self.focus[self.active].and_then(|id| self.get(id)).filter(|w| w.state != State::Minimized)
    }

    /// No window focused on the active workspace: the desktop's icons
    /// take the keys (ADR 0156).
    pub fn unfocus(&mut self) {
        self.focus[self.active] = None;
    }

    /// Focus and raise `id`, restoring it if minimised.
    pub fn focus(&mut self, id: WinId) {
        let Some(i) = self.windows.iter().position(|w| w.id == id) else { return };
        let mut w = self.windows.remove(i);
        if w.state == State::Minimized {
            w.state = w.before;
        }
        self.active = w.workspace;
        self.focus[w.workspace] = Some(id);
        self.windows.push(w);
    }

    pub fn minimize(&mut self, id: WinId) {
        let Some(w) = self.get_mut(id) else { return };
        if w.state == State::Minimized {
            return;
        }
        w.before = w.state;
        w.state = State::Minimized;
        let ws = w.workspace;
        if self.focus[ws] == Some(id) {
            self.focus[ws] = self.top_on(ws, Some(id));
        }
    }

    /// Maximise, or back to normal.
    pub fn toggle_maximize(&mut self, id: WinId) {
        if let Some(w) = self.get_mut(id) {
            w.state = if w.state == State::Maximized { State::Normal } else { State::Maximized };
        }
    }

    /// The frame `id` is drawn in.
    pub fn frame(&self, id: WinId) -> Option<Area> {
        let w = self.get(id)?;
        Some(match w.state {
            State::Normal | State::Minimized => w.rect,
            s => self.snap_area_in(s, self.screen_of(&w.rect)),
        })
    }

    /// Whether `id` fills its frame edge to edge (no radius, no shadow).
    pub fn flush(&self, id: WinId) -> bool {
        self.get(id).is_some_and(|w| w.state.flush())
    }

    /// The sizes window `id`'s app asks for (logical pixels; 0: none): the
    /// smallest it takes, and the size it would like. The preferred size
    /// applies until the person resizes the window; the window stays
    /// centred where it was and on the work area.
    pub fn hints(&mut self, id: WinId, min: (f32, f32), size: (f32, f32)) {
        let Some(r) = self.get(id).map(|w| w.rect) else { return };
        let (wk, extra_h) = (self.screen_of(&r), self.extra_h());
        let Some(w) = self.get_mut(id) else { return };
        w.min = (min.0.max(MIN_W).min(wk.w), min.1.max(MIN_H).min(wk.h));
        let r = w.rect;
        let (mut nw, mut nh) = (r.w, r.h);
        if !w.sized && size.0 > 0.0 && size.1 > 0.0 {
            (nw, nh) = (size.0, size.1);
        }
        let (mut nw, mut nh) = (round(nw.max(w.min.0).min(wk.w)), round(nh.max(w.min.1).min(wk.h)));
        if let Some(st) = w.steps {
            (nw, nh) = st.frame((nw, nh), w.min, extra_h);
            (nw, nh) = (nw.min(wk.w), nh.min(wk.h));
        }
        let x = round(r.x + (r.w - nw) / 2.0).clamp(wk.x, (wk.right() - nw).max(wk.x));
        let y = round(r.y + (r.h - nh) / 2.0).clamp(wk.y, (wk.bottom() - nh).max(wk.y));
        w.rect = Area::new(x, y, nw, nh);
    }

    /// The steps window `id`'s app resizes in (content logical pixels;
    /// a step under a pixel: none on that axis). Its frame is brought to
    /// a whole number of them at once.
    pub fn steps(&mut self, id: WinId, base: (f32, f32), step: (f32, f32)) {
        let Some(r) = self.get(id).map(|w| w.rect) else { return };
        let (wk, extra_h) = (self.screen_of(&r), self.extra_h());
        let Some(w) = self.get_mut(id) else { return };
        w.steps = (step.0 >= 1.0 || step.1 >= 1.0).then_some(Steps { base, step });
        if let Some(st) = w.steps {
            let r = w.rect;
            let (nw, nh) = st.frame((r.w, r.h), w.min, extra_h);
            w.rect = Area::new(r.x, r.y, nw.min(wk.w), nh.min(wk.h));
        }
    }

    /// Window `id`'s size in its steps (a terminal's columns and rows),
    /// if its app resizes in steps.
    pub fn size_in_steps(&self, id: WinId) -> Option<(u32, u32)> {
        let w = self.get(id)?;
        let st = w.steps?;
        let a = self.frame(id)?;
        Some(st.of((a.w, a.h), self.extra_h()))
    }

    /// The shown windows' frames, bottom first.
    pub fn layout(&self) -> Vec<(WinId, Area)> {
        self.visible().iter().filter_map(|w| self.frame(w.id).map(|a| (w.id, a))).collect()
    }

    /// The frames of workspace `ws`'s shown windows, bottom first.
    pub fn layout_on(&self, ws: usize) -> Vec<(WinId, Area)> {
        self.windows
            .iter()
            .filter(|w| w.workspace == ws && w.state != State::Minimized)
            .filter_map(|w| self.frame(w.id).map(|a| (w.id, a)))
            .collect()
    }

    /// What is at (x, y): the topmost window there, and which part.
    pub fn hit(&self, x: f32, y: f32) -> Option<Hit> {
        for (id, a) in self.layout().into_iter().rev() {
            let flush = self.flush(id);
            let grip = if flush { 0.0 } else { GRIP };
            if !a.grow(grip).contains(x, y) {
                continue;
            }
            let [min, max, close] = draw::buttons(a, self.title_h);
            if close.contains(x, y) {
                return Some(Hit::Close(id));
            }
            if max.contains(x, y) {
                return Some(Hit::Maximize(id));
            }
            if min.contains(x, y) {
                return Some(Hit::Minimize(id));
            }
            if !flush {
                let e = Edges {
                    left: x < a.x + GRIP / 2.0,
                    right: x > a.right() - GRIP / 2.0,
                    top: y < a.y + GRIP / 2.0,
                    bottom: y > a.bottom() - GRIP / 2.0,
                };
                if e != Edges::default() {
                    return Some(Hit::Edge(id, e));
                }
            }
            if y < a.y + self.title_h {
                return Some(Hit::Title(id));
            }
            return Some(Hit::Content(id));
        }
        None
    }

    /// Move a normal window's frame to `x`, `y`, keeping its title bar
    /// reachable (below the panel, at least 80 px on screen).
    pub fn move_to(&mut self, id: WinId, x: f32, y: f32) {
        // Anywhere on the displays together (ADR 0170); never above the
        // primary's panel.
        let title_h = self.title_h;
        let all = self.screens().fold(self.work, |a, s| {
            let (x0, y0) = (a.x.min(s.x), a.y.min(s.y));
            Area::new(x0, y0, a.right().max(s.right()) - x0, a.bottom().max(s.bottom()) - y0)
        });
        let wk = self.work;
        if let Some(w) = self.get_mut(id) {
            let r = &mut w.rect;
            r.x = round(x).clamp(all.x - r.w + 80.0, all.right() - 80.0);
            let top = if r.x + r.w > wk.x && r.x < wk.right() { wk.y.max(all.y) } else { all.y };
            r.y = round(y).clamp(top, all.bottom() - title_h);
        }
    }

    /// Resize a normal window from `start` (its frame when the drag began)
    /// by (dx, dy) on `edges`.
    pub fn resize(&mut self, id: WinId, start: Area, edges: Edges, dx: f32, dy: f32) {
        let (min_w, min_h) = self.get(id).map_or((MIN_W, MIN_H), |w| w.min);
        let steps = self.get(id).and_then(|w| w.steps);
        let mut r = start;
        if edges.right {
            r.w = (start.w + dx).max(min_w);
        }
        if edges.bottom {
            r.h = (start.h + dy).max(min_h);
        }
        if edges.left {
            let w = (start.w - dx).max(min_w);
            r.x = start.right() - w;
            r.w = w;
        }
        if edges.top {
            let h = (start.h - dy).max(min_h);
            r.y = (start.bottom() - h).max(self.screen_of(&start).y);
            r.h = start.bottom() - r.y;
        }
        let mut r = Area::new(round(r.x), round(r.y), round(r.w), round(r.h));
        // In whole steps, from the edge that stays where it was.
        if let Some(st) = steps {
            let (nw, nh) = st.frame((r.w, r.h), (min_w, min_h), self.extra_h());
            if edges.left {
                r.x = r.right() - nw;
            }
            if edges.top {
                r.y = (r.bottom() - nh).max(self.screen_of(&start).y);
            }
            r.w = nw;
            r.h = nh;
        }
        if let Some(w) = self.get_mut(id) {
            w.rect = r;
            w.sized = true;
        }
    }

    /// Where dragging a window to (x, y) would put it (ADR 0039, ADR
    /// 0102): a corner snaps to its quarter, the top edge maximises, the
    /// left and right edges snap to a half.
    /// On several displays, only edges no other display touches snap
    /// (crossing from one to the next doesn't).
    pub fn snap_target(&self, x: f32, y: f32) -> Option<State> {
        let wk = self.screen_at(x, y);
        let beside = |px: f32| self.screens().any(|s| s != wk && s.contains(px, y));
        let left = x <= wk.x + 1.0 && !beside(wk.x - 2.0);
        let right = x >= wk.right() - 2.0 && !beside(wk.right() + 2.0);
        let (top, bottom) = (y <= wk.y + CORNER, y >= wk.bottom() - CORNER);
        match (left, right, top, bottom) {
            (true, _, true, _) => Some(State::TopLeft),
            (true, _, _, true) => Some(State::BottomLeft),
            (_, true, true, _) => Some(State::TopRight),
            (_, true, _, true) => Some(State::BottomRight),
            _ if y <= wk.y + 1.0 => Some(State::Maximized),
            (true, ..) => Some(State::Left),
            (_, true, ..) => Some(State::Right),
            _ => None,
        }
    }

    /// The frame a snapped or maximised window gets on the primary display.
    pub fn snap_area(&self, state: State) -> Area {
        self.snap_area_in(state, self.work)
    }

    /// The frame a snapped or maximised window gets on the display under
    /// (x, y).
    pub fn snap_area_at(&self, state: State, x: f32, y: f32) -> Area {
        self.snap_area_in(state, self.screen_at(x, y))
    }

    fn snap_area_in(&self, state: State, wk: Area) -> Area {
        let (half, mid) = (round(wk.w / 2.0), round(wk.h / 2.0));
        let (l, r) = ((wk.x, half), (wk.x + half, wk.w - half));
        let (t, b) = ((wk.y, mid), (wk.y + mid, wk.h - mid));
        let quarter = |(x, w): (f32, f32), (y, h): (f32, f32)| Area::new(x, y, w, h);
        match state {
            State::Left => Area::new(wk.x, wk.y, half, wk.h),
            State::Right => Area::new(wk.x + half, wk.y, wk.w - half, wk.h),
            State::TopLeft => quarter(l, t),
            State::TopRight => quarter(r, t),
            State::BottomLeft => quarter(l, b),
            State::BottomRight => quarter(r, b),
            _ => wk,
        }
    }

    /// Snap or maximise `id`, keeping its normal frame for later.
    pub fn snap(&mut self, id: WinId, state: State) {
        if let Some(w) = self.get_mut(id) {
            w.state = state;
        }
    }

    /// Back to normal from maximised or snapped, keeping the normal size
    /// (a drag of a maximised window's title bar).
    pub fn restore(&mut self, id: WinId) {
        if let Some(w) = self.get_mut(id) {
            w.state = State::Normal;
        }
    }

    pub fn workspaces(&self) -> [Workspace; WORKSPACES] {
        core::array::from_fn(|i| {
            if i == self.active {
                Workspace::Active
            } else if self.windows.iter().any(|w| w.workspace == i) {
                Workspace::Used
            } else {
                Workspace::Empty
            }
        })
    }

    /// Carry out a command. Returns whether anything changed. Close,
    /// Terminal, Launcher and Quit are the session's.
    pub fn apply(&mut self, c: Command) -> bool {
        let focused = self.focused().map(|w| w.id);
        match c {
            Command::Workspace(n) if n < WORKSPACES && n != self.active => {
                self.active = n;
                true
            }
            Command::MoveToWorkspace(n) if n < WORKSPACES && n != self.active => {
                let Some(id) = focused else { return false };
                let ws = self.active;
                if let Some(w) = self.get_mut(id) {
                    w.workspace = n;
                }
                self.focus[ws] = self.top_on(ws, Some(id));
                self.focus[n] = Some(id);
                true
            }
            Command::Maximize | Command::Minimize | Command::SnapLeft | Command::SnapRight => {
                let Some(id) = focused else { return false };
                let state = self.get(id).map_or(State::Normal, |w| w.state);
                // From a half, up and down go to its quarters; from a
                // quarter, sideways to the quarter beside it, and back to
                // the half (ADR 0102).
                let to = match (c, state) {
                    (Command::Maximize, State::Left) => Some(State::TopLeft),
                    (Command::Maximize, State::Right) => Some(State::TopRight),
                    (Command::Minimize, State::Left) => Some(State::BottomLeft),
                    (Command::Minimize, State::Right) => Some(State::BottomRight),
                    (Command::Minimize, State::TopLeft) | (Command::Maximize, State::BottomLeft) => Some(State::Left),
                    (Command::Minimize, State::TopRight) | (Command::Maximize, State::BottomRight) => {
                        Some(State::Right)
                    }
                    (Command::SnapRight, State::TopLeft) => Some(State::TopRight),
                    (Command::SnapRight, State::BottomLeft) => Some(State::BottomRight),
                    (Command::SnapLeft, State::TopRight) => Some(State::TopLeft),
                    (Command::SnapLeft, State::BottomRight) => Some(State::BottomLeft),
                    (Command::SnapLeft, s) => Some(if s == State::Left { State::Normal } else { State::Left }),
                    (Command::SnapRight, s) => Some(if s == State::Right { State::Normal } else { State::Right }),
                    (Command::Maximize, _) => {
                        self.toggle_maximize(id);
                        None
                    }
                    _ => {
                        self.minimize(id);
                        None
                    }
                };
                if let (Some(to), Some(w)) = (to, self.get_mut(id)) {
                    w.state = to;
                }
                true
            }
            Command::Cycle => {
                // The bottom window of the workspace comes to the top.
                let next =
                    self.windows.iter().find(|w| w.workspace == self.active && Some(w.id) != focused).map(|w| w.id);
                next.is_some_and(|id| {
                    self.focus(id);
                    true
                })
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slate_display::input::{
        KEY_1, KEY_ENTER, KEY_ESC, KEY_LEFT, KEY_LEFTMETA, KEY_Q, KEY_RIGHT, KEY_RIGHTMETA, KEY_SPACE, KEY_TAB, KEY_UP,
    };

    #[test]
    fn bindings() {
        assert_eq!(binding(KEY_1 + 2, true, false, false), Some(Command::Workspace(2)));
        assert_eq!(binding(KEY_1, true, true, false), Some(Command::MoveToWorkspace(0)));
        assert_eq!(binding(KEY_LEFT, true, false, false), Some(Command::SnapLeft));
        assert_eq!(binding(KEY_UP, true, false, false), Some(Command::Maximize));
        assert_eq!(binding(KEY_TAB, false, false, true), Some(Command::Cycle));
        assert_eq!(binding(KEY_Q, true, false, false), Some(Command::Close));
        assert_eq!(binding(KEY_ENTER, true, false, false), Some(Command::Terminal));
        assert_eq!(binding(KEY_Q, false, false, false), None);
        // The logo key alone (its release: the logo bit off).
        assert_eq!(binding(KEY_LEFTMETA, false, false, false), Some(Command::Applications));
        assert_eq!(binding(KEY_RIGHTMETA, false, false, false), Some(Command::Applications));
        assert_eq!(binding(KEY_LEFTMETA, true, false, false), None);
        assert_eq!(binding(KEY_SPACE, false, false, true), Some(Command::TitleButtons));
        assert_eq!(binding(KEY_SPACE, true, false, false), Some(Command::Launcher));
    }

    #[test]
    fn title_bar_keys() {
        use draw::TitleButton::{Close, Maximize, Minimize};
        assert_eq!(title_key(Close, KEY_LEFT, false), Some(TitleKey::Focus(Maximize)));
        assert_eq!(title_key(Close, KEY_RIGHT, false), Some(TitleKey::Focus(Minimize)));
        assert_eq!(title_key(Minimize, KEY_LEFT, false), Some(TitleKey::Focus(Close)));
        assert_eq!(title_key(Minimize, KEY_TAB, false), Some(TitleKey::Focus(Maximize)));
        assert_eq!(title_key(Maximize, KEY_TAB, true), Some(TitleKey::Focus(Minimize)));
        assert_eq!(title_key(Maximize, KEY_ENTER, false), Some(TitleKey::Press(Maximize)));
        assert_eq!(title_key(Close, KEY_SPACE, false), Some(TitleKey::Press(Close)));
        assert_eq!(title_key(Close, KEY_ESC, false), Some(TitleKey::Leave));
        assert_eq!(title_key(Close, KEY_Q, false), None);
    }

    #[test]
    fn placing_stacking_and_states() {
        let mut wm = Wm::new(1280.0, 800.0);
        let a = wm.add("a", None, false);
        let b = wm.add("b", None, false);
        // Centred near 60% x 70%, cascading, below the panel.
        let (ra, rb) = (wm.frame(a).unwrap(), wm.frame(b).unwrap());
        assert_eq!((ra.w, ra.h), (768.0, 538.0));
        assert_eq!((rb.x - ra.x, rb.y - ra.y), (24.0, 24.0));
        assert!(ra.y >= 32.0);
        // b is on top: the overlap is b's.
        let (x, y) = (rb.x + 50.0, rb.y + 100.0);
        assert_eq!(wm.hit(x, y), Some(Hit::Content(b)));
        // Clicking a part of a showing through raises it.
        wm.focus(a);
        assert_eq!(wm.hit(x, y), Some(Hit::Content(a)));
        assert_eq!(wm.visible().last().map(|w| w.id), Some(a));
        // The title bar, its buttons, the edges.
        assert_eq!(wm.hit(ra.x + 40.0, ra.y + 10.0), Some(Hit::Title(a)));
        let [min, max, close] = draw::buttons(ra, wm.title_h);
        assert_eq!(wm.hit(close.x + 5.0, close.y + 5.0), Some(Hit::Close(a)));
        assert_eq!(wm.hit(max.x + 5.0, max.y + 5.0), Some(Hit::Maximize(a)));
        assert_eq!(wm.hit(min.x + 5.0, min.y + 5.0), Some(Hit::Minimize(a)));
        assert!(matches!(wm.hit(ra.right() + 1.0, ra.y + 200.0), Some(Hit::Edge(_, Edges { right: true, .. }))));
        // Maximised fills the work area; minimised hides and passes focus.
        assert!(wm.apply(Command::Maximize));
        assert_eq!(wm.frame(a), Some(wm.work));
        assert!(wm.apply(Command::Minimize));
        assert_eq!(wm.focused().map(|w| w.id), Some(b));
        assert_eq!(wm.visible().len(), 1);
        // Focusing a minimised window brings it back maximised.
        wm.focus(a);
        assert_eq!(wm.frame(a), Some(wm.work));
        assert!(wm.apply(Command::SnapLeft));
        assert_eq!(wm.frame(a), Some(Area::new(0.0, 32.0, 640.0, 768.0)));
        // alt + tab: the other window.
        assert!(wm.apply(Command::Cycle));
        assert_eq!(wm.focused().map(|w| w.id), Some(b));
    }

    #[test]
    fn moving_and_resizing() {
        let mut wm = Wm::new(1280.0, 800.0);
        let a = wm.add("a", None, false);
        let start = wm.frame(a).unwrap();
        wm.move_to(a, 5000.0, -100.0);
        let r = wm.frame(a).unwrap();
        assert_eq!((r.x, r.y), (1200.0, 32.0));
        wm.resize(a, r, Edges { left: true, top: false, right: false, bottom: true }, 100.0, -9999.0);
        let r2 = wm.frame(a).unwrap();
        assert_eq!((r2.w, r2.h), (start.w - 100.0, MIN_H));
        assert_eq!(r2.right(), r.right());
    }

    /// The Strata scenario's corner drag: just outside a frame's corner
    /// is its resize band.
    #[test]
    fn corner_band() {
        let mut wm = Wm::new(1280.0, 800.0);
        let _ = wm.add("terminal", None, false);
        let k = wm.add("keys", None, true);
        wm.move_to(k, 420.0, 211.0);
        let r = wm.frame(k).unwrap();
        std::println!("{r:?}");
        let corner = Edges { left: false, top: false, right: true, bottom: true };
        assert_eq!(wm.hit(r.right() + 2.0, r.bottom() + 2.0), Some(Hit::Edge(k, corner)));
    }

    #[test]
    fn quarters() {
        let mut wm = Wm::new(1280.0, 800.0);
        let a = wm.add("a", None, false);
        // super + left, then up: the top-left quarter; right: the top-right;
        // down: back to the right half; down again: its bottom quarter.
        let steps = [
            (Command::SnapLeft, State::Left),
            (Command::Maximize, State::TopLeft),
            (Command::SnapRight, State::TopRight),
            (Command::Minimize, State::Right),
            (Command::Minimize, State::BottomRight),
            (Command::SnapLeft, State::BottomLeft),
            (Command::Maximize, State::Left),
        ];
        for (c, want) in steps {
            assert!(wm.apply(c));
            assert_eq!(wm.get(a).unwrap().state, want, "{c:?}");
        }
        wm.snap(a, State::BottomRight);
        assert_eq!(wm.frame(a), Some(Area::new(640.0, 416.0, 640.0, 384.0)));
        assert!(wm.flush(a));
        // Dragged to a corner: its quarter; to the edges: halves and all.
        assert_eq!(wm.snap_target(0.0, 40.0), Some(State::TopLeft));
        assert_eq!(wm.snap_target(1279.0, 799.0), Some(State::BottomRight));
        assert_eq!(wm.snap_target(0.0, 400.0), Some(State::Left));
        assert_eq!(wm.snap_target(640.0, 32.0), Some(State::Maximized));
        assert_eq!(wm.snap_target(640.0, 400.0), None);
    }

    #[test]
    fn size_hints() {
        let mut wm = Wm::new(1280.0, 800.0);
        let a = wm.add("a", None, false);
        let before = wm.frame(a).unwrap();
        // The app would like 600 x 400 and takes no less than 400 x 300:
        // the window takes that size about its centre.
        wm.hints(a, (400.0, 300.0), (600.0, 400.0));
        let r = wm.frame(a).unwrap();
        assert_eq!((r.w, r.h), (600.0, 400.0));
        assert!((r.x + r.w / 2.0 - (before.x + before.w / 2.0)).abs() <= 1.0);
        // Resizing stops at its minimum, and then the preferred size no
        // longer applies.
        wm.resize(a, r, Edges { right: true, bottom: true, ..Edges::default() }, -500.0, -500.0);
        assert_eq!(wm.frame(a).map(|r| (r.w, r.h)), Some((400.0, 300.0)));
        wm.hints(a, (400.0, 300.0), (900.0, 700.0));
        assert_eq!(wm.frame(a).map(|r| (r.w, r.h)), Some((400.0, 300.0)));
        // A minimum larger than the screen is cut to it.
        wm.hints(a, (5000.0, 5000.0), (0.0, 0.0));
        assert_eq!(wm.frame(a), Some(wm.work));
    }

    /// A theme's taller title bar and top bar (ADR 0167): the work area
    /// starts under the bar, windows move below it, frames grow by the
    /// title bar's difference for the same content.
    #[test]
    fn theme_shape() {
        let mut wm = Wm::new(1280.0, 800.0);
        let t = wm.add("terminal", None, false);
        wm.get_mut(t).unwrap().rect = Area::new(100.0, 32.0, 600.0, 400.0);
        let (base, step) = ((32.0, 24.0), (7.8, 21.0));
        wm.steps(t, base, step);
        let rows = wm.size_in_steps(t).unwrap().1;
        wm.shape(40.0, 36.0);
        assert_eq!((wm.work.y, wm.work.bottom(), wm.extra_h()), (36.0, 800.0, 41.0));
        assert_eq!(wm.frame(t).unwrap().y, 36.0);
        let [_, _, close] = draw::buttons(wm.frame(t).unwrap(), wm.title_h);
        assert_eq!(close.y, 36.0 + 8.0);
        assert_eq!(wm.hit(300.0, 36.0 + 38.0), Some(Hit::Title(t)));
        // The same rows need a frame 4 px taller.
        let h = base.1 + rows as f32 * step.1 + 0.5;
        wm.hints(t, (0.0, 0.0), (600.0, h.ceil() + wm.extra_h()));
        assert_eq!(wm.size_in_steps(t).unwrap().1, rows);
    }

    #[test]
    fn steps() {
        let mut wm = Wm::new(1280.0, 800.0);
        let t = wm.add("terminal", None, false);
        // A terminal: 16 px of padding each side, cells of 7.8 x 21.
        let (base, step) = ((32.0, 24.0), (7.8, 21.0));
        let extra_h = wm.extra_h();
        let cells = |c: f32, r: f32| (base.0 + c * step.0 + EXTRA_W, base.1 + r * step.1 + extra_h);
        let (w, h) = cells(80.0, 24.0);
        wm.hints(t, (0.0, 0.0), (w, h));
        wm.steps(t, base, step);
        assert_eq!(wm.size_in_steps(t), Some((80, 24)));
        // A drag to the right and down by a few cells and a bit: whole
        // cells, with the half pixel the app's rounding needs.
        let start = wm.frame(t).unwrap();
        wm.resize(t, start, Edges { right: true, bottom: true, ..Edges::default() }, 3.0 * 7.8 + 5.0, 2.0 * 21.0 + 9.0);
        let r = wm.frame(t).unwrap();
        assert_eq!(wm.size_in_steps(t), Some((83, 26)));
        assert_eq!((r.x, r.y), (start.x, start.y));
        let content_w = r.w - EXTRA_W - base.0;
        assert!((83.0 * 7.8..84.0 * 7.8).contains(&content_w), "{content_w}");
        // From the left edge the right edge stays put.
        let start = r;
        wm.resize(t, start, Edges { left: true, ..Edges::default() }, 10.0 * 7.8 - 2.0, 0.0);
        let r = wm.frame(t).unwrap();
        assert_eq!(wm.size_in_steps(t), Some((73, 26)));
        assert_eq!(r.right(), start.right());
        // Never under the minimum: the steps round up to it.
        wm.resize(t, r, Edges { right: true, bottom: true, ..Edges::default() }, -2000.0, -2000.0);
        let r = wm.frame(t).unwrap();
        assert!(r.w >= MIN_W && r.h >= MIN_H);
        let (c, rows) = wm.size_in_steps(t).unwrap();
        assert!(cells(c as f32, rows as f32).0 <= r.w && cells(c as f32 + 1.0, rows as f32).0 > r.w);
        // Maximised, it fills the screen whatever its steps.
        wm.toggle_maximize(t);
        assert_eq!(wm.frame(t), Some(wm.work));
        // Steps of nothing: none.
        wm.steps(t, (0.0, 0.0), (0.0, 0.0));
        assert_eq!(wm.size_in_steps(t), None);
    }

    #[test]
    fn workspaces_and_closing() {
        let mut wm = Wm::new(1280.0, 800.0);
        let a = wm.add("a", None, false);
        let b = wm.add("b", None, false);
        assert!(wm.apply(Command::MoveToWorkspace(2)));
        assert_eq!(wm.focused().map(|w| w.id), Some(a));
        assert_eq!(wm.workspaces(), [Workspace::Active, Workspace::Empty, Workspace::Used, Workspace::Empty]);
        assert!(wm.apply(Command::Workspace(2)));
        assert_eq!(wm.focused().map(|w| w.id), Some(b));
        wm.remove(b);
        assert!(wm.focused().is_none());
        assert!(wm.apply(Command::Workspace(0)));
        wm.remove(a);
        assert!(wm.visible().is_empty());
    }

    #[test]
    fn two_displays() {
        // The primary 1280x800 with a 32 px panel, another 1024x768 to its
        // right.
        let mut wm = Wm::new(1280.0, 800.0);
        wm.set_screens(1280.0, 800.0, 32.0, alloc::vec![Area::new(1280.0, 0.0, 1024.0, 768.0)]);
        assert!(wm.in_bar(100.0, 10.0) && !wm.in_bar(1400.0, 10.0) && !wm.in_bar(100.0, 40.0));
        let a = wm.add("terminal", None, false);
        // Moved onto the second display, past where one display stops it.
        wm.move_to(a, 1500.0, 5.0);
        let r = wm.frame(a).unwrap();
        assert_eq!((r.x, r.y), (1500.0, 5.0));
        // Maximised there: the second display's area, without a panel.
        wm.snap(a, State::Maximized);
        assert_eq!(wm.frame(a), Some(Area::new(1280.0, 0.0, 1024.0, 768.0)));
        wm.snap(a, State::Normal);
        // The shared edge doesn't snap; the outer ones do.
        assert_eq!(wm.snap_target(1279.0, 400.0), None);
        assert_eq!(wm.snap_target(1281.0, 400.0), None);
        assert_eq!(wm.snap_target(2302.0, 400.0), Some(State::Right));
        assert_eq!(wm.snap_target(0.0, 400.0), Some(State::Left));
        assert_eq!(wm.snap_area_at(State::Left, 2000.0, 300.0), Area::new(1280.0, 0.0, 512.0, 768.0));
        // The second display goes: its window comes back to the primary.
        wm.set_screens(1280.0, 800.0, 32.0, alloc::vec![]);
        let r = wm.frame(a).unwrap();
        assert!(wm.work.contains(r.x + r.w / 2.0, r.y + r.h / 2.0), "{r:?}");
        // Nearest display for a point on none.
        assert_eq!(wm.screen_at(5000.0, 100.0), wm.work);
    }
}
