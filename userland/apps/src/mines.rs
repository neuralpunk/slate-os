// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mines (ADR 0177): the mines genre, in Slate's own look.
//!
//! - **The rules** (the genre's): mines hide under a grid of squares.
//!   Opening a square shows how many mines touch it; one that none touch
//!   opens its neighbours too. The first square opened is never a mine,
//!   nor next to one: the mines are laid after it. A flag marks a mine
//!   (and keeps its square from opening); opening a number whose flags
//!   are all placed opens the rest around it. Every square without a mine
//!   open wins; a mine opened loses, and shows the others.
//! - **Sizes:** small (9 by 9, 10 mines), medium (16 by 16, 40) and large
//!   (30 by 16, 99); the size and each one's best time are remembered
//!   (`~/.config/strata/mines`).
//! - **Playing:** click opens, the right button flags (and unflags), a
//!   click or double-click on a number opens around it. Keys: the arrows
//!   move, Space or Enter opens, f flags, ctrl + n starts again.
//! - **The look:** unopened squares raised, open ones sunk into the well;
//!   the numbers in the theme's semantic colours (readable in every
//!   theme), mines and flags drawn as shapes.

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{KEY_DOWN, KEY_ENTER, KEY_KPENTER, KEY_LEFT, KEY_RIGHT, KEY_UP};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::CTRL;
use slate_ui::Color;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::path::Path;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Now};

const KEY_SPACE: u16 = 57;

/// A board size: its name, columns, rows and mines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub name: &'static str,
    pub cols: usize,
    pub rows: usize,
    pub mines: usize,
}

pub const SIZES: [Size; 3] = [
    Size { name: "small", cols: 9, rows: 9, mines: 10 },
    Size { name: "medium", cols: 16, rows: 16, mines: 40 },
    Size { name: "large", cols: 30, rows: 16, mines: 99 },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Square {
    pub mine: bool,
    pub open: bool,
    pub flag: bool,
    /// Mines touching it.
    pub near: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No square opened yet (the mines aren't laid).
    Fresh,
    Playing,
    Won,
    /// Lost, on this square.
    Lost(usize),
}

/// A board and how it stands.
#[derive(Clone, Debug)]
pub struct Board {
    pub size: Size,
    pub squares: Vec<Square>,
    pub state: State,
    seed: u64,
}

impl Board {
    pub fn new(size: Size, seed: u64) -> Board {
        Board { size, squares: alloc::vec![Square::default(); size.cols * size.rows], state: State::Fresh, seed }
    }

    pub fn at(&self, c: usize, r: usize) -> usize {
        r * self.size.cols + c
    }

    /// The squares around `i` (up to eight).
    pub fn around(&self, i: usize) -> Vec<usize> {
        let (cols, rows) = (self.size.cols as isize, self.size.rows as isize);
        let (c, r) = ((i % self.size.cols) as isize, (i / self.size.cols) as isize);
        let mut v = Vec::with_capacity(8);
        for dr in -1..=1 {
            for dc in -1..=1 {
                let (nc, nr) = (c + dc, r + dr);
                if (dc, dr) != (0, 0) && (0..cols).contains(&nc) && (0..rows).contains(&nr) {
                    v.push((nr * cols + nc) as usize);
                }
            }
        }
        v
    }

    /// Lay the mines anywhere but on `first` and around it (the first
    /// square opened is always a clear one).
    fn lay(&mut self, first: usize) {
        let mut keep = self.around(first);
        keep.push(first);
        let mut free: Vec<usize> = (0..self.squares.len()).filter(|i| !keep.contains(i)).collect();
        let mut s = self.seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        s = (s ^ (s >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        s = (s ^ (s >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let mut s = (s ^ (s >> 31)).max(1);
        for _ in 0..self.size.mines.min(free.len()) {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let k = (s.wrapping_mul(0x2545_F491_4F6C_DD1D) % free.len() as u64) as usize;
            let m = free.swap_remove(k);
            self.squares[m].mine = true;
        }
        for i in 0..self.squares.len() {
            let n = self.around(i).iter().filter(|&&j| self.squares[j].mine).count();
            self.squares[i].near = n as u8;
        }
    }

    pub fn flags(&self) -> usize {
        self.squares.iter().filter(|s| s.flag).count()
    }

    fn over(&self) -> bool {
        matches!(self.state, State::Won | State::Lost(_))
    }

    /// Open square `i` (and, if no mine touches it, its neighbours, and
    /// theirs). Whether anything opened.
    pub fn open(&mut self, i: usize) -> bool {
        if self.over() || self.squares[i].flag || self.squares[i].open {
            return false;
        }
        if self.state == State::Fresh {
            self.lay(i);
            self.state = State::Playing;
        }
        if self.squares[i].mine {
            self.squares[i].open = true;
            self.state = State::Lost(i);
            return true;
        }
        let mut stack = alloc::vec![i];
        while let Some(j) = stack.pop() {
            let sq = &mut self.squares[j];
            if sq.open || sq.flag {
                continue;
            }
            sq.open = true;
            if sq.near == 0 {
                stack.extend(self.around(j).into_iter().filter(|&k| !self.squares[k].open && !self.squares[k].mine));
            }
        }
        if self.squares.iter().all(|s| s.open || s.mine) {
            self.state = State::Won;
            // The mines left are flagged for it.
            for s in &mut self.squares {
                s.flag = s.mine;
            }
        }
        true
    }

    /// Flag or unflag square `i`.
    pub fn flag(&mut self, i: usize) -> bool {
        if self.over() || self.squares[i].open {
            return false;
        }
        self.squares[i].flag = !self.squares[i].flag;
        true
    }

    /// Open around number `i` when its flags are all placed.
    pub fn chord(&mut self, i: usize) -> bool {
        let sq = self.squares[i];
        if self.over() || !sq.open || sq.near == 0 {
            return false;
        }
        let around = self.around(i);
        if around.iter().filter(|&&j| self.squares[j].flag).count() != usize::from(sq.near) {
            return false;
        }
        let mut any = false;
        for j in around {
            any |= self.open(j);
        }
        any
    }
}

/// The window.
#[derive(Debug)]
pub struct Mines {
    pub board: Board,
    pub size: usize,
    pub cursor: usize,
    pub keys_used: bool,
    /// Best seconds per size.
    pub best: [Option<u32>; 3],
    started: Option<i64>,
    ended: Option<i64>,
    pub now: i64,
    pub status: String,
    seed: u64,
    /// Where things were drawn: the board, its squares' size, the size
    /// tabs and the face button.
    grid: Area,
    tile: f32,
    tabs: Vec<Area>,
    pub live: bool,
}

impl Mines {
    pub fn new(size: usize, seed: u64) -> Mines {
        let size = size.min(SIZES.len() - 1);
        crate::trace!("mines: {} board", SIZES[size].name);
        Mines {
            board: Board::new(SIZES[size], seed),
            size,
            cursor: 0,
            keys_used: false,
            best: [None; 3],
            started: None,
            ended: None,
            now: 0,
            status: String::new(),
            seed,
            grid: Area::new(0.0, 0.0, 0.0, 0.0),
            tile: 24.0,
            tabs: Vec::new(),
            live: false,
        }
    }

    pub fn new_game(&mut self) {
        self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.board = Board::new(SIZES[self.size], self.seed);
        self.started = None;
        self.ended = None;
        self.status.clear();
        self.cursor = self.cursor.min(self.board.squares.len() - 1);
        crate::trace!("mines: new {} board", SIZES[self.size].name);
    }

    fn seconds(&self) -> u32 {
        match self.started {
            Some(s) => ((self.ended.unwrap_or(self.now) - s).max(0) / 1000) as u32,
            None => 0,
        }
    }

    /// After a move: the clock, the end, the best time.
    fn after(&mut self) {
        if self.started.is_none() && self.board.state != State::Fresh {
            self.started = Some(self.now);
        }
        match self.board.state {
            State::Won if self.ended.is_none() => {
                self.ended = Some(self.now);
                let secs = self.seconds();
                let best = &mut self.best[self.size];
                if best.is_none_or(|b| secs < b) {
                    *best = Some(secs);
                    self.status = String::from("Cleared, a best time.");
                    self.save();
                } else {
                    self.status = String::from("Cleared.");
                }
                crate::trace!("mines: cleared in {secs}s");
            }
            State::Lost(i) if self.ended.is_none() => {
                self.ended = Some(self.now);
                self.status = String::from("A mine. ctrl n starts again.");
                crate::trace!("mines: lost at {},{}", i % self.board.size.cols, i / self.board.size.cols);
            }
            _ => {}
        }
    }

    fn save(&self) {
        if !self.live {
            return;
        }
        let mut t = alloc::format!("size={}\n", SIZES[self.size].name);
        for (s, b) in SIZES.iter().zip(self.best) {
            if let Some(b) = b {
                t += &alloc::format!("best-{}={b}\n", s.name);
            }
        }
        let _ = kit::save_config("mines", &t);
    }

    pub fn load(&mut self, text: &str) {
        for l in text.lines() {
            let Some((k, v)) = l.split_once('=') else { continue };
            if k == "size"
                && let Some(i) = SIZES.iter().position(|s| s.name == v.trim())
            {
                self.size = i;
                self.board = Board::new(SIZES[i], self.seed);
            }
            if let Some(name) = k.strip_prefix("best-")
                && let Some(i) = SIZES.iter().position(|s| s.name == name)
            {
                self.best[i] = v.trim().parse().ok();
            }
        }
    }

    fn square_at(&self, x: f32, y: f32) -> Option<usize> {
        if !self.grid.contains(x, y) {
            return None;
        }
        let c = ((x - self.grid.x) / self.tile) as usize;
        let r = ((y - self.grid.y) / self.tile) as usize;
        (c < self.board.size.cols && r < self.board.size.rows).then(|| self.board.at(c, r))
    }

    fn open(&mut self, i: usize) {
        let sq = self.board.squares[i];
        let opened = if sq.open { self.board.chord(i) } else { self.board.open(i) };
        if opened {
            crate::trace!("mines: opened, {} open", self.board.squares.iter().filter(|s| s.open).count());
        }
        self.after();
    }

    fn flag(&mut self, i: usize) {
        if self.board.flag(i) {
            crate::trace!("mines: {} flags", self.board.flags());
        }
    }
}

/// A mine's shape in `a`: a ball with spikes.
fn mine(p: &mut Painter<'_>, a: Area, c: Color) {
    let (cx, cy, r) = (a.x + a.w / 2.0, a.y + a.h / 2.0, a.w * 0.22);
    p.path(&Path::circle(cx, cy, r), c);
    let w = (a.w * 0.07).max(1.5);
    for k in 0..4 {
        let t = k as f32 * core::f32::consts::FRAC_PI_4;
        let (dx, dy) = (slate_ui::icon::cos(t) * r * 1.55, slate_ui::icon::sin(t) * r * 1.55);
        p.polyline(&[(cx - dx, cy - dy), (cx + dx, cy + dy)], w, c);
    }
}

impl App for Mines {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let b = &self.board;
        let (cols, rows) = (b.size.cols as f32, b.size.rows as f32);
        // The header: sizes, mines left, time.
        self.tabs = kit::tabs(p, pal, f, a.x + 12.0, a.y + 10.0, &["small", "medium", "large"], self.size);
        let left = b.size.mines as isize - b.flags() as isize;
        let secs = self.seconds();
        let facts = alloc::format!("{left} mines · {}:{:02}", secs / 60, secs % 60);
        let st = p.style(&f.mono, 12.0, pal.muted);
        let w = p.measure(&st, &facts);
        p.line(&st, a.x + a.w - 16.0 - w, a.y + 15.0, 20.0, &facts);
        // The board, as big as fits.
        let room = Area::new(a.x + 16.0, a.y + 52.0, a.w - 32.0, a.h - 52.0 - 44.0);
        self.tile = (room.w / cols).min(room.h / rows).clamp(14.0, 44.0);
        self.tile = ((self.tile) as i32) as f32;
        let (gw, gh) = (self.tile * cols, self.tile * rows);
        self.grid = Area::new(room.x + (room.w - gw).max(0.0) / 2.0, room.y + (room.h - gh).max(0.0) / 2.0, gw, gh);
        let g = self.grid;
        p.fill(g.grow(4.0), 8.0, pal.well);
        let lost = matches!(b.state, State::Lost(_));
        let colours = [
            pal.accents.steel.text,
            pal.accents.sage.text,
            pal.accents.clay.text,
            pal.accents.heather.text,
            pal.accents.ochre.text,
            pal.accents.moss.text,
            pal.text_1,
            pal.muted,
        ];
        let num_size = (self.tile * 0.55).clamp(10.0, 22.0);
        for (i, sq) in b.squares.iter().enumerate() {
            let (c, r) = ((i % b.size.cols) as f32, (i / b.size.cols) as f32);
            let t = Area::new(g.x + c * self.tile, g.y + r * self.tile, self.tile, self.tile).grow(-1.0);
            let shown_mine = sq.mine && (sq.open || (lost && !sq.flag));
            if sq.open || shown_mine {
                // Open: sunk into the board (its well shows), the mine that
                // lost tinted.
                if b.state == State::Lost(i) {
                    p.fill(t, 3.0, pal.accents.clay.tint);
                }
                if sq.mine {
                    mine(p, t, if b.state == State::Lost(i) { pal.accents.clay.text } else { pal.text_2 });
                } else if sq.near > 0 {
                    let n = alloc::format!("{}", sq.near);
                    let style = p.style(&f.semibold, num_size, colours[usize::from(sq.near - 1)]);
                    let nw = p.measure(&style, &n);
                    p.line(&style, t.x + (t.w - nw) / 2.0, t.y, t.h, &n);
                }
            } else {
                // Shut: a tile standing up, lit along its top, its lower
                // edge in shadow.
                // (A light theme's raised colour is near its well's: the
                // window's white stands up there.)
                p.fill(t, 3.0, if pal.light() { pal.window } else { pal.raised });
                p.fill(Area::new(t.x + 2.0, t.y, t.w - 4.0, 1.0), 0.0, pal.border_strong);
                p.fill(Area::new(t.x + 2.0, t.y + t.h - 1.0, t.w - 4.0, 1.0), 0.0, pal.border);
                if sq.flag {
                    // A flag on a mine that wasn't: crossed out when lost.
                    let wrong = lost && !sq.mine;
                    let s = t.w * 0.7;
                    p.icon(Icon::Flag, t.x + (t.w - s) / 2.0, t.y + (t.h - s) / 2.0, s, pal.accents.clay.text);
                    if wrong {
                        p.polyline(&[(t.x + 4.0, t.y + 4.0), (t.x + t.w - 4.0, t.y + t.h - 4.0)], 1.5, pal.text_1);
                    }
                }
            }
            if self.keys_used && i == self.cursor {
                p.border(t.grow(1.0), 4.0, 2.0, pal.focus);
            }
        }
        // The status, or the keys.
        if self.status.is_empty() {
            kit::hints(
                p,
                pal,
                f,
                a,
                &[("click", "open"), ("right", "flag"), ("click a number", "open around"), ("ctrl n", "new game")],
            );
        } else {
            let best =
                self.best[self.size].map_or(String::new(), |b| alloc::format!(" · best {}:{:02}", b / 60, b % 60));
            let m = p.style(&f.regular, 12.0, pal.text_3);
            p.line(&m, a.x + 20.0, a.y + a.h - 28.0, 18.0, &alloc::format!("{}{best}", self.status));
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let (cols, rows) = (self.board.size.cols, self.board.size.rows);
        let (c, r) = (self.cursor % cols, self.cursor / cols);
        match (code, ch) {
            (_, Some('n')) if mods & CTRL != 0 => self.new_game(),
            (KEY_LEFT | KEY_RIGHT | KEY_UP | KEY_DOWN, _) if !self.keys_used => self.keys_used = true,
            (KEY_LEFT, _) => self.cursor = self.board.at((c + cols - 1) % cols, r),
            (KEY_RIGHT, _) => self.cursor = self.board.at((c + 1) % cols, r),
            (KEY_UP, _) => self.cursor = self.board.at(c, (r + rows - 1) % rows),
            (KEY_DOWN, _) => self.cursor = self.board.at(c, (r + 1) % rows),
            (KEY_ENTER | KEY_KPENTER | KEY_SPACE, _) => {
                self.keys_used = true;
                self.open(self.cursor);
            }
            (_, Some('f')) => {
                self.keys_used = true;
                self.flag(self.cursor);
            }
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if let Some(i) = self.tabs.iter().position(|t| t.contains(x, y)) {
            if i != self.size {
                self.size = i;
                self.new_game();
                self.save();
            }
            return Effect::Redraw;
        }
        let Some(i) = self.square_at(x, y) else { return Effect::None };
        self.keys_used = false;
        self.cursor = i;
        self.open(i);
        Effect::Redraw
    }

    fn right_click(&mut self, x: f32, y: f32) -> Effect {
        let Some(i) = self.square_at(x, y) else { return Effect::None };
        self.keys_used = false;
        self.cursor = i;
        self.flag(i);
        Effect::Redraw
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        // A second click on an open number opens around it, as one does.
        match self.square_at(x, y) {
            Some(i) if self.board.squares[i].open => {
                self.board.chord(i);
                self.after();
                Effect::Redraw
            }
            _ => self.click(x, y),
        }
    }

    fn tick(&mut self, now: Now) -> bool {
        self.now = now.mono;
        self.started.is_some() && self.ended.is_none()
    }

    fn wake(&self, now: Now) -> Option<i64> {
        let s = self.started?;
        self.ended.is_none().then(|| 1000 - (now.mono - s).rem_euclid(1000))
    }
}

pub fn main() -> i32 {
    let mut seed = [0u8; 8];
    let _ = slate_rt::process::random(&mut seed);
    let mut m = Mines::new(0, u64::from_le_bytes(seed));
    if let Some(t) = kit::load_config("mines") {
        m.load(&t);
    }
    m.live = true;
    kit::run("mines", "mines", None, Hints { min: (360, 420), size: (560, 640) }, &mut m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_square_is_clear() {
        for seed in 0..50 {
            let mut b = Board::new(SIZES[1], seed);
            let first = b.at(5, 7);
            assert!(b.open(first));
            assert_eq!(b.squares.iter().filter(|s| s.mine).count(), 40);
            assert!(!b.squares[first].mine && b.squares[first].near == 0, "seed {seed}");
            // A zero opens its neighbours.
            assert!(b.around(first).iter().all(|&j| b.squares[j].open));
        }
    }

    /// A board laid by hand: a mine in the corner of a 3 by 3.
    fn tiny() -> Board {
        let mut b = Board::new(Size { name: "tiny", cols: 3, rows: 3, mines: 1 }, 1);
        b.squares[0].mine = true;
        for i in 0..9 {
            b.squares[i].near = b.around(i).iter().filter(|&&j| b.squares[j].mine).count() as u8;
        }
        b.state = State::Playing;
        b
    }

    #[test]
    fn opening_flagging_and_ending() {
        // Opening the far corner opens everything but the mine: won, and
        // the mine flagged.
        let mut b = tiny();
        assert!(b.open(8));
        assert_eq!(b.state, State::Won);
        assert!(b.squares[0].flag);
        // A flag keeps its square shut; opening a mine loses.
        let mut b = tiny();
        b.flag(0);
        assert!(!b.open(0));
        b.flag(0);
        assert!(b.open(0));
        assert_eq!(b.state, State::Lost(0));
        assert!(!b.open(8), "nothing after the end");
        // Around a number: only with its flags placed.
        let mut b = tiny();
        b.open(4);
        assert_eq!(b.squares[4].near, 1);
        assert!(!b.chord(4), "no flag yet");
        b.flag(0);
        assert!(b.chord(4));
        assert_eq!(b.state, State::Won);
        // A wrong flag opens the mine.
        let mut b = tiny();
        b.open(4);
        b.flag(1);
        assert!(b.chord(4));
        assert_eq!(b.state, State::Lost(0));
    }

    #[test]
    fn the_window() {
        let mut m = Mines::new(0, 9);
        m.grid = Area::new(0.0, 0.0, 9.0 * 20.0, 9.0 * 20.0);
        m.tile = 20.0;
        m.click(95.0, 95.0);
        assert!(m.board.squares[m.board.at(4, 4)].open);
        assert_ne!(m.board.state, State::Fresh);
        // Flags by the right button and by keys.
        let shut = (0..81).find(|&i| !m.board.squares[i].open).unwrap();
        m.right_click((shut % 9) as f32 * 20.0 + 5.0, (shut / 9) as f32 * 20.0 + 5.0);
        assert!(m.board.squares[shut].flag);
        m.cursor = shut;
        m.key(0, Some('f'), 0);
        assert!(!m.board.squares[shut].flag);
        // Remembered: the size and best times.
        m.load("size=large\nbest-small=42\n");
        assert_eq!((m.size, m.board.size.cols, m.best[0]), (2, 30, Some(42)));
        // Another size from its tab.
        m.tabs = alloc::vec![Area::new(0.0, 0.0, 10.0, 10.0), Area::new(20.0, 0.0, 10.0, 10.0)];
        m.click(25.0, 5.0);
        assert_eq!((m.size, m.board.size.mines), (1, 40));
    }
}
