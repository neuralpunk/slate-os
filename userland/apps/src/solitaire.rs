// SPDX-License-Identifier: MIT OR Apache-2.0

//! Solitaire (ADR 0177): Klondike, the traditional patience game, in
//! Slate's own look.
//!
//! - **The rules** (the game's, as card-game books give them): 52 cards; seven
//!   columns of one to seven cards, the top of each face up; the rest is
//!   the stock. Columns build down in alternating colours, and any run of
//!   face-up cards moves as one; only a King (or a run from one) goes into
//!   an empty column. The four foundations build up by suit from the Ace.
//!   The stock turns one card (or three) onto the waste, whose top card
//!   plays; an empty stock takes the waste back, as often as wanted. A
//!   face-down card left on top of a column turns up. All four
//!   foundations full wins.
//! - **Playing:** drag a card (and the cards on it) where it goes; click
//!   the stock to turn; double-click a card to send it to its foundation.
//!   Keys: the arrows choose a pile (up and down a column's face-up
//!   cards), Enter or Space picks up and puts down, Esc puts back, d turns
//!   the stock, f sends the chosen card to its foundation, ctrl + z undoes,
//!   ctrl + n deals again. Once every card is face up and the stock and
//!   waste are empty, the game finishes itself, a card at a time.
//! - **The look:** warm paper cards, their suits drawn (no font has them),
//!   hearts and diamonds in a muted red. The backs are Slate's own: a
//!   landscape of sediment, wavy bands in the stratum colours (ochre,
//!   rust, terracotta, sage, olive, slate) framed in deep ink, a paper
//!   medallion in the middle; the same in every theme, as printed cards
//!   are. The table is the window. Moves and time in the corner. "Draw one" or
//!   "draw three" is remembered (`~/.config/strata/solitaire`).

use alloc::string::String;
use alloc::vec::Vec;

use slate_display::input::{KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_LEFT, KEY_RIGHT, KEY_UP};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::CTRL;
use slate_ui::Color;
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::path::Path;
use slate_ui::shadow::BoxShadow;
use slate_ui::ui::Area;

use crate::kit::{self, App, Effect, Hints, Now};

const KEY_SPACE: u16 = 57;

/// A card: rank 1 (Ace) to 13 (King); suit 0 spades, 1 hearts, 2
/// diamonds, 3 clubs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    pub rank: u8,
    pub suit: u8,
    pub up: bool,
}

impl Card {
    pub fn red(&self) -> bool {
        self.suit == 1 || self.suit == 2
    }
}

/// Where cards lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pile {
    Stock,
    Waste,
    Found(usize),
    Tab(usize),
}

/// The cards on the table.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Table {
    pub stock: Vec<Card>,
    pub waste: Vec<Card>,
    pub found: [Vec<Card>; 4],
    pub tab: [Vec<Card>; 7],
}

impl Table {
    pub fn pile(&self, p: Pile) -> &Vec<Card> {
        match p {
            Pile::Stock => &self.stock,
            Pile::Waste => &self.waste,
            Pile::Found(i) => &self.found[i],
            Pile::Tab(i) => &self.tab[i],
        }
    }

    fn pile_mut(&mut self, p: Pile) -> &mut Vec<Card> {
        match p {
            Pile::Stock => &mut self.stock,
            Pile::Waste => &mut self.waste,
            Pile::Found(i) => &mut self.found[i],
            Pile::Tab(i) => &mut self.tab[i],
        }
    }
}

/// A shuffled deck from `seed` (xorshift64*, Fisher-Yates).
fn shuffled(seed: u64) -> Vec<Card> {
    let mut deck: Vec<Card> =
        (0..4).flat_map(|suit| (1..=13).map(move |rank| Card { rank, suit, up: false })).collect();
    // The seed mixed first (splitmix64), so neighbouring seeds deal
    // unrelated games; xorshift needs a state other than zero.
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut s = (z ^ (z >> 31)).max(1);
    let mut next = || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    for i in (1..deck.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        deck.swap(i, j);
    }
    deck
}

/// A game: the table, how it plays, and what can be undone.
#[derive(Clone, Debug)]
pub struct Game {
    pub table: Table,
    pub draw3: bool,
    pub moves: u32,
    undo: Vec<(Table, u32)>,
}

impl Game {
    /// Deal from `seed`: column `i` gets `i + 1` cards, its top face up.
    pub fn deal(seed: u64, draw3: bool) -> Game {
        let mut deck = shuffled(seed);
        let mut t = Table::default();
        for (i, column) in t.tab.iter_mut().enumerate() {
            for k in 0..=i {
                let mut c = deck.pop().unwrap_or(Card { rank: 1, suit: 0, up: false });
                c.up = k == i;
                column.push(c);
            }
        }
        deck.iter_mut().for_each(|c| c.up = false);
        t.stock = deck;
        Game { table: t, draw3, moves: 0, undo: Vec::new() }
    }

    pub fn won(&self) -> bool {
        self.table.found.iter().all(|f| f.len() == 13)
    }

    fn save(&mut self) {
        self.undo.push((self.table.clone(), self.moves));
        if self.undo.len() > 500 {
            self.undo.remove(0);
        }
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn undo(&mut self) -> bool {
        match self.undo.pop() {
            Some((t, m)) => {
                self.table = t;
                self.moves = m;
                true
            }
            None => false,
        }
    }

    /// Turn the stock: one card (or three) onto the waste, face up; an
    /// empty stock takes the waste back. Whether anything moved.
    pub fn draw(&mut self) -> bool {
        if self.table.stock.is_empty() && self.table.waste.is_empty() {
            return false;
        }
        self.save();
        let t = &mut self.table;
        if t.stock.is_empty() {
            while let Some(mut c) = t.waste.pop() {
                c.up = false;
                t.stock.push(c);
            }
        } else {
            for _ in 0..if self.draw3 { 3 } else { 1 } {
                let Some(mut c) = t.stock.pop() else { break };
                c.up = true;
                t.waste.push(c);
            }
        }
        self.moves += 1;
        true
    }

    /// Whether the cards of `from` from `index` on may be picked up: the
    /// top of the waste or a foundation, or a column's face-up run.
    pub fn movable(&self, from: Pile, index: usize) -> bool {
        let pile = self.table.pile(from);
        match from {
            Pile::Stock => false,
            Pile::Waste | Pile::Found(_) => index + 1 == pile.len(),
            Pile::Tab(_) => {
                let Some(run) = pile.get(index..) else { return false };
                !run.is_empty()
                    && run.iter().all(|c| c.up)
                    && run.windows(2).all(|w| w[0].red() != w[1].red() && w[0].rank == w[1].rank + 1)
            }
        }
    }

    /// Whether `cards` (a run, its lowest card first) may go onto `to`.
    pub fn fits(&self, cards: &[Card], to: Pile) -> bool {
        let Some(first) = cards.first() else { return false };
        let pile = self.table.pile(to);
        match to {
            Pile::Stock | Pile::Waste => false,
            Pile::Found(_) => {
                cards.len() == 1
                    && match pile.last() {
                        None => first.rank == 1,
                        Some(top) => top.suit == first.suit && first.rank == top.rank + 1,
                    }
            }
            Pile::Tab(_) => match pile.last() {
                None => first.rank == 13,
                Some(top) => top.up && top.red() != first.red() && top.rank == first.rank + 1,
            },
        }
    }

    /// Move the cards of `from` from `index` onto `to`, if the rules allow;
    /// a face-down card left on top of a column turns up.
    pub fn play(&mut self, from: Pile, index: usize, to: Pile) -> bool {
        if from == to || !self.movable(from, index) {
            return false;
        }
        let run: Vec<Card> = self.table.pile(from)[index..].to_vec();
        if !self.fits(&run, to) {
            return false;
        }
        self.save();
        self.table.pile_mut(from).truncate(index);
        self.table.pile_mut(to).extend(run);
        if let Pile::Tab(_) = from
            && let Some(top) = self.table.pile_mut(from).last_mut()
        {
            top.up = true;
        }
        self.moves += 1;
        true
    }

    /// Where a double-click sends pile `from`'s top card: its foundation.
    pub fn foundation_for(&self, from: Pile) -> Option<Pile> {
        let card = *self.table.pile(from).last()?;
        let index = self.table.pile(from).len() - 1;
        if !self.movable(from, index) || matches!(from, Pile::Found(_)) {
            return None;
        }
        (0..4).map(Pile::Found).find(|&f| self.fits(&[card], f))
    }

    /// Whether the game can finish by itself: stock and waste empty,
    /// every card face up (then every card can go home in order).
    pub fn finishable(&self) -> bool {
        let t = &self.table;
        !self.won() && t.stock.is_empty() && t.waste.is_empty() && t.tab.iter().all(|c| c.iter().all(|c| c.up))
    }

    /// One step of finishing: the lowest card that can go home does.
    pub fn finish_step(&mut self) -> bool {
        let mut best: Option<(u8, Pile)> = None;
        for i in 0..7 {
            if let Some(c) = self.table.tab[i].last()
                && self.foundation_for(Pile::Tab(i)).is_some()
                && best.is_none_or(|(r, _)| c.rank < r)
            {
                best = Some((c.rank, Pile::Tab(i)));
            }
        }
        let Some((_, from)) = best else { return false };
        let Some(to) = self.foundation_for(from) else { return false };
        let index = self.table.pile(from).len() - 1;
        self.play(from, index, to)
    }
}

// --- Layout ------------------------------------------------------------------

/// Where everything is in a window `a`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Layout {
    pub card: (f32, f32),
    pub top: f32,
    pub tab_y: f32,
    pub left: f32,
    pub gap: f32,
    pub bottom: f32,
}

const HEADER: f32 = 48.0;
const FOOTER: f32 = 40.0;

impl Layout {
    pub fn of(a: Area) -> Layout {
        let gap = 14.0;
        let cw = ((a.w - 32.0 - 6.0 * gap) / 7.0).clamp(48.0, 120.0);
        let ch = ((cw * 1.4) as i32) as f32;
        let width = 7.0 * cw + 6.0 * gap;
        let left = a.x + ((a.w - width) / 2.0).max(16.0);
        let top = a.y + HEADER;
        Layout { card: (cw, ch), top, tab_y: top + ch + 22.0, left, gap, bottom: a.y + a.h - FOOTER }
    }

    fn column_x(&self, i: usize) -> f32 {
        self.left + i as f32 * (self.card.0 + self.gap)
    }

    /// A pile's own place (its first card's).
    pub fn slot(&self, p: Pile) -> Area {
        let (cw, ch) = self.card;
        match p {
            Pile::Stock => Area::new(self.column_x(0), self.top, cw, ch),
            Pile::Waste => Area::new(self.column_x(1), self.top, cw, ch),
            Pile::Found(i) => Area::new(self.column_x(3 + i), self.top, cw, ch),
            Pile::Tab(i) => Area::new(self.column_x(i), self.tab_y, cw, ch),
        }
    }

    /// The steps down a column: face-down cards and face-up ones, closer
    /// when the column would run past the bottom.
    fn steps(&self, column: &[Card]) -> (f32, f32) {
        let ch = self.card.1;
        let (mut down, mut up) = (ch * 0.12, ch * 0.28);
        let downs = column.iter().filter(|c| !c.up).count() as f32;
        let ups = column.iter().filter(|c| c.up).count().saturating_sub(1) as f32;
        let room = self.bottom - self.tab_y - ch;
        let need = downs * down + ups * up;
        if need > room && need > 0.0 {
            let k = (room / need).max(0.25);
            (down, up) = (down * k, up * k);
        }
        (down, up)
    }

    /// Where card `k` of a column lies.
    pub fn in_column(&self, i: usize, column: &[Card], k: usize) -> Area {
        let (down, up) = self.steps(column);
        let y = self.tab_y + column[..k].iter().map(|c| if c.up { up } else { down }).sum::<f32>();
        Area::new(self.column_x(i), y, self.card.0, self.card.1)
    }

    /// Where waste card `k` of `n` lies: three show fanned when drawing
    /// three.
    fn in_waste(&self, n: usize, k: usize, draw3: bool) -> Area {
        let s = self.slot(Pile::Waste);
        if !draw3 {
            return s;
        }
        // The last three turned, left to right (the column between the
        // waste and the foundations is free for them).
        let first = n.saturating_sub(3);
        let i = k.saturating_sub(first) as f32;
        Area::new(s.x + i * (self.card.0 * 0.3).max(26.0), s.y, s.w, s.h)
    }
}

// --- The window ----------------------------------------------------------------

/// What is held: from where, from which card, and where the pointer took
/// it (or, by keys, not moving).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Held {
    pub from: Pile,
    pub index: usize,
    /// The pointer's offset in the first held card, and where it is.
    pub grab: (f32, f32),
    pub at: (f32, f32),
    pub moved: bool,
    pub by_keys: bool,
}

#[derive(Debug)]
pub struct Solitaire {
    pub game: Game,
    pub held: Option<Held>,
    /// The keys' place: a pile, and a card in a column; shown once the
    /// keys have been used.
    pub cursor: (Pile, usize),
    pub keys_used: bool,
    pub status: String,
    seed: u64,
    /// When the first move was made, and when it was won (monotonic ms);
    /// the time shown.
    started: Option<i64>,
    won_at: Option<i64>,
    pub now: i64,
    finishing: bool,
    layout: Layout,
    tabs: Vec<Area>,
    new_button: Area,
    /// The draw mode for the next deal.
    pub next_draw3: bool,
}

/// The ranks as written on cards.
fn rank_text(r: u8) -> &'static str {
    ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"][usize::from(r.clamp(1, 13) - 1)]
}

/// Card colours: the same in every theme (cards are paper).
const PAPER: Color = Color::rgb(0xF7F4EE);
const PAPER_EDGE: Color = Color::rgb(0xCBC5BA);
const INK: Color = Color::rgb(0x1E1C1A);
/// The red suits: Sediment's clay, 5.6:1 on the paper.
const RED: Color = Color::rgb(0xA3452F);
/// The backs: the frame's ink, and the strata from the top down (the
/// Sediment wallpaper's bands, ADR 0167).
const BACK_INK: Color = Color::rgb(0x2F3340);
const STRATA: [u32; 6] = [0xD9A441, 0xC9874B, 0xB5643C, 0x8A9A6B, 0x6E7A5A, 0x4B5563];

impl Solitaire {
    pub fn new(seed: u64, draw3: bool) -> Solitaire {
        let game = Game::deal(seed, draw3);
        crate::trace!("solitaire: dealt ({})", if draw3 { "draw three" } else { "draw one" });
        Solitaire {
            game,
            held: None,
            cursor: (Pile::Stock, 0),
            keys_used: false,
            status: String::new(),
            seed,
            started: None,
            won_at: None,
            now: 0,
            finishing: false,
            layout: Layout::of(Area::new(0.0, 0.0, 760.0, 600.0)),
            tabs: Vec::new(),
            new_button: Area::new(0.0, 0.0, 0.0, 0.0),
            next_draw3: draw3,
        }
    }

    pub fn new_game(&mut self) {
        self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let draw3 = self.next_draw3;
        *self = Solitaire { layout: self.layout, now: self.now, ..Solitaire::new(self.seed, draw3) };
    }

    /// Solved after `ms` (the scenes).
    #[cfg(test)]
    pub fn won_for_scene(&mut self, ms: i64) {
        self.started = Some(0);
        self.won_at = Some(ms);
    }

    fn moved(&mut self) {
        if self.started.is_none() {
            self.started = Some(self.now);
        }
        self.status.clear();
        if self.game.won() && self.won_at.is_none() {
            self.won_at = Some(self.now);
            crate::trace!("solitaire: won in {} moves", self.game.moves);
        } else if self.game.finishable() && !self.finishing {
            self.finishing = true;
            crate::trace!("solitaire: finishing by itself");
        }
    }

    fn seconds(&self) -> i64 {
        match self.started {
            Some(s) => (self.won_at.unwrap_or(self.now) - s).max(0) / 1000,
            None => 0,
        }
    }

    /// The pile and card at (x, y): the topmost card under it, or the
    /// pile's empty place.
    pub fn hit(&self, x: f32, y: f32) -> Option<(Pile, usize)> {
        let l = &self.layout;
        let t = &self.game.table;
        for (i, col) in t.tab.iter().enumerate() {
            for k in (0..col.len()).rev() {
                if l.in_column(i, col, k).contains(x, y) {
                    return Some((Pile::Tab(i), k));
                }
            }
            if col.is_empty() && l.slot(Pile::Tab(i)).contains(x, y) {
                return Some((Pile::Tab(i), 0));
            }
        }
        for p in [Pile::Stock, Pile::Found(0), Pile::Found(1), Pile::Found(2), Pile::Found(3)] {
            if l.slot(p).contains(x, y) {
                return Some((p, t.pile(p).len().saturating_sub(1)));
            }
        }
        let n = t.waste.len();
        if n > 0 && l.in_waste(n, n - 1, self.game.draw3).contains(x, y) {
            return Some((Pile::Waste, n - 1));
        }
        None
    }

    /// The pile a held run would go to, dropped with its first card at
    /// (x, y): the pile it overlaps most.
    fn drop_target(&self, card: Area) -> Option<Pile> {
        let l = &self.layout;
        let mut best: Option<(f32, Pile)> = None;
        let piles = (0..4).map(Pile::Found).chain((0..7).map(Pile::Tab));
        for p in piles {
            let pile = self.game.table.pile(p);
            let target = match p {
                Pile::Tab(i) if !pile.is_empty() => {
                    let last = l.in_column(i, pile, pile.len() - 1);
                    Area::new(last.x, last.y, last.w, last.h)
                }
                _ => l.slot(p),
            };
            let ox = (card.x + card.w).min(target.x + target.w) - card.x.max(target.x);
            let oy = (card.y + card.h).min(target.y + target.h) - card.y.max(target.y);
            if ox > 0.0 && oy > 0.0 && best.is_none_or(|(b, _)| ox * oy > b) {
                best = Some((ox * oy, p));
            }
        }
        best.map(|(_, p)| p)
    }

    fn try_play(&mut self, from: Pile, index: usize, to: Pile) -> bool {
        let ok = self.game.play(from, index, to);
        if ok {
            crate::trace!("solitaire: moved {from:?} to {to:?}");
            self.moved();
        }
        ok
    }

    fn draw_stock(&mut self) {
        if self.game.draw() {
            crate::trace!("solitaire: turned the stock ({} left)", self.game.table.stock.len());
            self.moved();
        }
    }

    fn send_home(&mut self, from: Pile) -> bool {
        match self.game.foundation_for(from) {
            Some(to) => {
                let index = self.game.table.pile(from).len() - 1;
                self.try_play(from, index, to)
            }
            None => false,
        }
    }

    fn undo(&mut self) {
        self.held = None;
        self.finishing = false;
        if self.game.undo() {
            self.status = String::from("Undone.");
        }
    }

    /// The cursor's order of piles, left to right: the top row, then the
    /// columns.
    fn piles_in_row(top: bool) -> Vec<Pile> {
        if top {
            alloc::vec![Pile::Stock, Pile::Waste, Pile::Found(0), Pile::Found(1), Pile::Found(2), Pile::Found(3)]
        } else {
            (0..7).map(Pile::Tab).collect()
        }
    }

    /// The first face-up card of a column (where the keys land on it).
    fn first_up(&self, i: usize) -> usize {
        let col = &self.game.table.tab[i];
        col.iter().position(|c| c.up).unwrap_or(col.len().saturating_sub(1))
    }

    fn cursor_to(&mut self, p: Pile) {
        let k = match p {
            Pile::Tab(i) => self.game.table.tab[i].len().saturating_sub(1),
            _ => self.game.table.pile(p).len().saturating_sub(1),
        };
        self.cursor = (p, k);
    }

    /// Enter or Space on the cursor: pick up there, or put down there.
    fn keys_act(&mut self) {
        let (p, k) = self.cursor;
        if let Some(h) = self.held.filter(|h| h.by_keys) {
            self.held = None;
            if !self.try_play(h.from, h.index, p) {
                self.status = String::from("That can't go there.");
            }
            self.cursor_to(p);
            return;
        }
        match p {
            Pile::Stock => self.draw_stock(),
            _ if self.game.movable(p, k) => {
                self.held =
                    Some(Held { from: p, index: k, grab: (0.0, 0.0), at: (0.0, 0.0), moved: false, by_keys: true });
            }
            _ => {}
        }
    }
}

// --- Drawing ----------------------------------------------------------------------

/// Suit `suit`'s mark, centred at (cx, cy), `s` across.
fn suit_mark(p: &mut Painter<'_>, suit: u8, cx: f32, cy: f32, s: f32, c: Color) {
    let h = s / 2.0;
    match suit {
        // Diamonds.
        2 => {
            let mut d = Path::new();
            d.move_to(cx, cy - h).line_to(cx + h * 0.72, cy).line_to(cx, cy + h).line_to(cx - h * 0.72, cy).close();
            p.path(&d, c);
        }
        // Hearts: two lobes and a point.
        1 => {
            let r = h * 0.52;
            p.path(&Path::circle(cx - r * 0.92, cy - h * 0.28, r), c);
            p.path(&Path::circle(cx + r * 0.92, cy - h * 0.28, r), c);
            let mut v = Path::new();
            v.move_to(cx - h * 0.98, cy - h * 0.12).line_to(cx + h * 0.98, cy - h * 0.12).line_to(cx, cy + h).close();
            p.path(&v, c);
        }
        // Spades: a heart upside down, and a stem.
        0 => {
            let r = h * 0.48;
            p.path(&Path::circle(cx - r * 0.95, cy + h * 0.18, r), c);
            p.path(&Path::circle(cx + r * 0.95, cy + h * 0.18, r), c);
            let mut v = Path::new();
            v.move_to(cx - h * 0.94, cy + h * 0.06).line_to(cx + h * 0.94, cy + h * 0.06).line_to(cx, cy - h).close();
            p.path(&v, c);
            let mut stem = Path::new();
            stem.move_to(cx, cy + h * 0.2).line_to(cx + h * 0.32, cy + h).line_to(cx - h * 0.32, cy + h).close();
            p.path(&stem, c);
        }
        // Clubs: three leaves and a stem.
        _ => {
            let r = h * 0.42;
            p.path(&Path::circle(cx, cy - h * 0.5, r), c);
            p.path(&Path::circle(cx - h * 0.5, cy + h * 0.08, r), c);
            p.path(&Path::circle(cx + h * 0.5, cy + h * 0.08, r), c);
            let mut stem = Path::new();
            stem.move_to(cx, cy - h * 0.1).line_to(cx + h * 0.3, cy + h).line_to(cx - h * 0.3, cy + h).close();
            p.path(&stem, c);
        }
    }
}

/// A card in `a`: its face, or its back.
fn draw_card(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, c: Card, lit: bool) {
    let r = (a.w * 0.08).clamp(4.0, 8.0);
    let soft = BoxShadow { dx: 0.0, dy: 1.0, blur: 3.0, spread: 0.0, color: Color::rgb(0).with_alpha(60) };
    p.shadow(a, r, &soft);
    if !c.up {
        draw_back(p, a, r);
        return;
    }
    p.fill(a, r, PAPER);
    p.border(a, r, 1.0, if lit { pal.focus } else { PAPER_EDGE });
    let ink = if c.red() { RED } else { INK };
    let size = (a.w * 0.2).clamp(11.0, 18.0);
    let rank = p.style(&f.semibold, size, ink);
    p.line(&rank, a.x + 6.0, a.y + 3.0, size * 1.3, rank_text(c.rank));
    suit_mark(p, c.suit, a.x + 6.0 + size * 0.35, a.y + 6.0 + size * 1.55, size * 0.62, ink);
    suit_mark(p, c.suit, a.x + a.w * 0.58, a.y + a.h * 0.6, a.w * 0.42, ink);
    if lit {
        p.border(a.grow(1.5), r + 1.5, 2.0, pal.focus);
    }
}

/// A card's back in `a` (corner radius `r`): the strata landscape.
fn draw_back(p: &mut Painter<'_>, a: Area, r: f32) {
    p.fill(a, r, BACK_INK);
    let inner = a.grow(-(a.w * 0.07).clamp(3.0, 6.0));
    let clip = p.clip(inner);
    // Each band from its wavy top edge down to the bottom, the next one
    // over it: two waves of different lengths make the edges uneven, as
    // rock is.
    let n = STRATA.len();
    let step = inner.h / n as f32;
    let amp = (inner.h * 0.035).max(1.5);
    let seg = (inner.w / 14.0).max(2.0);
    for (k, &colour) in STRATA.iter().enumerate() {
        let base = inner.y + k as f32 * step - if k == 0 { amp * 2.0 } else { 0.0 };
        let phase = k as f32 * 1.7;
        let wave = |x: f32| {
            let t = (x - inner.x) / inner.w * core::f32::consts::TAU;
            base + amp * slate_ui::icon::sin(t * 1.5 + phase) + amp * 0.5 * slate_ui::icon::sin(t * 3.1 + phase * 2.3)
        };
        let mut band = Path::new();
        band.move_to(inner.x - 1.0, inner.y + inner.h + 1.0);
        let mut x = inner.x - 1.0;
        while x < inner.x + inner.w + seg {
            band.line_to(x, wave(x));
            x += seg;
        }
        band.line_to(inner.x + inner.w + 1.0, inner.y + inner.h + 1.0).close();
        p.path(&band, Color::rgb(colour));
    }
    p.unclip(clip);
    // A fine paper rule inside the frame, and the medallion.
    p.border(inner, (r - 2.0).max(2.0), 1.0, PAPER.with_alpha(120));
    let m = (a.w * 0.16).clamp(6.0, 14.0);
    let (cx, cy) = (a.x + a.w / 2.0, a.y + a.h / 2.0);
    p.path(&Path::circle(cx, cy, m), BACK_INK);
    p.path(&Path::circle(cx, cy, m - 1.5), PAPER);
    let mut d = Path::new();
    d.move_to(cx, cy - m * 0.55).line_to(cx + m * 0.4, cy).line_to(cx, cy + m * 0.55).line_to(cx - m * 0.4, cy).close();
    p.path(&d, Color::rgb(STRATA[2]));
}

/// An empty pile's place.
fn draw_slot(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area, label: &str, lit: bool) {
    let r = (a.w * 0.08).clamp(4.0, 8.0);
    p.fill(a, r, pal.well);
    p.border(a, r, 1.0, if lit { pal.focus } else { pal.border });
    if !label.is_empty() {
        let st = p.style(&f.mono, 11.0, pal.muted);
        let w = p.measure(&st, label);
        p.line(&st, a.x + (a.w - w) / 2.0, a.y + a.h / 2.0 - 9.0, 18.0, label);
    }
}

impl App for Solitaire {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        let l = Layout::of(a);
        if l != self.layout {
            // Where the first column's top card lies, and the step to the
            // next column (the apps scenario drags by them).
            let t = &self.game.table.tab[0];
            let top = if t.is_empty() { l.slot(Pile::Tab(0)) } else { l.in_column(0, t, t.len() - 1) };
            crate::trace!(
                "solitaire: column 0's top at {} {} {} {} and the columns {} apart",
                top.x,
                top.y,
                top.w,
                top.h,
                l.card.0 + l.gap
            );
        }
        self.layout = l;
        let t = self.game.table.clone();
        // The header: the draw mode, the moves and time.
        self.tabs =
            kit::tabs(p, pal, f, l.left - 4.0, a.y + 10.0, &["draw one", "draw three"], usize::from(self.next_draw3));
        let secs = self.seconds();
        let facts = alloc::format!("{} moves · {}:{:02}", self.game.moves, secs / 60, secs % 60);
        let st = p.style(&f.mono, 12.0, pal.muted);
        let w = p.measure(&st, &facts);
        let right = (l.left + 7.0 * l.card.0 + 6.0 * l.gap).min(a.x + a.w - 16.0);
        p.line(&st, right - w, a.y + 15.0, 20.0, &facts);
        let held = self.held.filter(|h| h.moved);
        let hidden = |pile: Pile, k: usize| held.is_some_and(|h| h.from == pile && k >= h.index);
        let keys_on = |pile: Pile, k: usize, s: &Solitaire| {
            s.keys_used
                && (s.cursor == (pile, k)
                    || (s.cursor.0 == pile && matches!(pile, Pile::Stock | Pile::Found(_) | Pile::Waste)))
        };
        let kh = self.held.filter(|h| h.by_keys);
        // The stock.
        let s = l.slot(Pile::Stock);
        match t.stock.last() {
            Some(&c) => draw_card(p, pal, f, s, c, keys_on(Pile::Stock, 0, self)),
            None => {
                draw_slot(p, pal, f, s, if t.waste.is_empty() { "" } else { "again" }, keys_on(Pile::Stock, 0, self))
            }
        }
        // The waste: its top, fanned to three when drawing three.
        let n = t.waste.len();
        let shown = if self.game.draw3 { 3.min(n) } else { 1.min(n) };
        if n == 0 {
            draw_slot(p, pal, f, l.slot(Pile::Waste), "", false);
        }
        for (k, &card) in t.waste.iter().enumerate().skip(n - shown) {
            if hidden(Pile::Waste, k) {
                continue;
            }
            let lit = k + 1 == n && (keys_on(Pile::Waste, k, self) || kh.is_some_and(|h| h.from == Pile::Waste));
            draw_card(p, pal, f, l.in_waste(n, k, self.game.draw3), card, lit);
        }
        // The foundations.
        for (i, pile) in t.found.iter().enumerate() {
            let lit = keys_on(Pile::Found(i), 0, self);
            let top = (0..pile.len()).rev().find(|&k| !hidden(Pile::Found(i), k));
            match top {
                Some(k) => draw_card(p, pal, f, l.slot(Pile::Found(i)), pile[k], lit),
                None => draw_slot(p, pal, f, l.slot(Pile::Found(i)), "A", lit),
            }
        }
        // The columns.
        for (i, col) in t.tab.iter().enumerate() {
            if col.is_empty() {
                draw_slot(p, pal, f, l.slot(Pile::Tab(i)), "K", self.keys_used && self.cursor.0 == Pile::Tab(i));
            }
            for (k, &c) in col.iter().enumerate() {
                if hidden(Pile::Tab(i), k) {
                    continue;
                }
                let lit = (self.keys_used && self.cursor.0 == Pile::Tab(i) && self.cursor.1 == k)
                    || kh.is_some_and(|h| h.from == Pile::Tab(i) && k >= h.index);
                let at = l.in_column(i, col, k);
                // A card under another shows only its top strip: draw no
                // more (the backs are worth the saving).
                let covered = (k + 1 < col.len() && !hidden(Pile::Tab(i), k + 1)).then(|| l.in_column(i, col, k + 1));
                let clip =
                    covered.map(|next| p.clip(Area::new(at.x - 4.0, at.y - 4.0, at.w + 8.0, next.y - at.y + 6.0)));
                draw_card(p, pal, f, at, c, lit);
                if let Some(c) = clip {
                    p.unclip(c);
                }
            }
        }
        // What the pointer holds, over everything.
        if let Some(h) = held {
            let run = &t.pile(h.from)[h.index..];
            let step = l.card.1 * 0.28;
            for (k, &c) in run.iter().enumerate() {
                let at = Area::new(h.at.0 - h.grab.0, h.at.1 - h.grab.1 + k as f32 * step, l.card.0, l.card.1);
                draw_card(p, pal, f, at, c, false);
            }
        }
        // Won.
        if self.won_at.is_some() {
            p.fill(a, 0.0, pal.dim_dialog);
            let w = 300.0;
            let d = Area::new(a.x + (a.w - w) / 2.0, a.y + a.h / 2.0 - 70.0, w, 140.0);
            p.fill(d, 12.0, pal.window);
            p.border(d, 12.0, 1.0, pal.border_strong);
            let big = p.style(&f.semibold, 20.0, pal.text_1);
            let text = "Solved";
            let tw = p.measure(&big, text);
            p.line(&big, d.x + (d.w - tw) / 2.0, d.y + 18.0, 28.0, text);
            let secs = self.seconds();
            let line = alloc::format!("{} moves in {}:{:02}", self.game.moves, secs / 60, secs % 60);
            let small = p.style(&f.regular, 13.0, pal.text_3);
            let lw = p.measure(&small, &line);
            p.line(&small, d.x + (d.w - lw) / 2.0, d.y + 50.0, 20.0, &line);
            self.new_button = Area::new(d.x + (d.w - 120.0) / 2.0, d.y + 88.0, 120.0, 32.0);
            kit::button(p, pal, f, self.new_button, "New game", true, true);
        }
        // The status, or the keys.
        if self.status.is_empty() {
            kit::hints(
                p,
                pal,
                f,
                a,
                &[
                    ("drag", "move"),
                    ("click", "turn"),
                    ("double-click", "home"),
                    ("ctrl z", "undo"),
                    ("ctrl n", "new game"),
                ],
            );
        } else {
            let m = p.style(&f.regular, 12.0, pal.text_3);
            p.line(&m, a.x + 20.0, a.y + a.h - 28.0, 18.0, &self.status);
        }
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if self.won_at.is_some() {
            if matches!(code, KEY_ENTER | KEY_KPENTER) || ch == Some('n') {
                self.new_game();
            }
            return Effect::Redraw;
        }
        let ctrl = mods & CTRL != 0;
        match (code, ch) {
            (_, Some('z')) if ctrl => self.undo(),
            (_, Some('n')) if ctrl => self.new_game(),
            (_, Some('d')) if !ctrl => self.draw_stock(),
            (_, Some('f')) if !ctrl => {
                if !self.send_home(self.cursor.0) {
                    self.status = String::from("Nothing there goes home yet.");
                }
            }
            (KEY_ESC, _) => self.held = None,
            (KEY_ENTER | KEY_KPENTER | KEY_SPACE, _) if !self.keys_used => self.keys_used = true,
            (KEY_ENTER | KEY_KPENTER | KEY_SPACE, _) => self.keys_act(),
            (KEY_LEFT | KEY_RIGHT | KEY_UP | KEY_DOWN, _) if !self.keys_used => self.keys_used = true,
            (KEY_LEFT | KEY_RIGHT, _) => {
                let top = !matches!(self.cursor.0, Pile::Tab(_));
                let row = Self::piles_in_row(top);
                let at = row.iter().position(|&p| p == self.cursor.0).unwrap_or(0);
                let next = if code == KEY_LEFT { (at + row.len() - 1) % row.len() } else { (at + 1) % row.len() };
                self.cursor_to(row[next]);
            }
            (KEY_UP | KEY_DOWN, _) => match self.cursor {
                (Pile::Tab(i), k) => {
                    let first = self.first_up(i);
                    let last = self.game.table.tab[i].len().saturating_sub(1);
                    if code == KEY_UP && k > first {
                        self.cursor.1 = k - 1;
                    } else if code == KEY_UP {
                        // Up out of the columns: the pile above.
                        // (Column 3 is under the free place.)
                        let row = Self::piles_in_row(true);
                        self.cursor_to(row[[0, 1, 1, 2, 3, 4, 5][i]]);
                    } else if k < last {
                        self.cursor.1 = k + 1;
                    }
                }
                (p, _) if code == KEY_DOWN => {
                    let row = Self::piles_in_row(true);
                    let at = row.iter().position(|&x| x == p).unwrap_or(0);
                    let col = if at >= 2 { at + 1 } else { at };
                    self.cursor_to(Pile::Tab(col.min(6)));
                    if let Pile::Tab(i) = self.cursor.0 {
                        self.cursor.1 = self.game.table.tab[i].len().saturating_sub(1);
                    }
                }
                _ => {}
            },
            _ => return Effect::None,
        }
        Effect::Redraw
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if self.won_at.is_some() {
            if self.new_button.contains(x, y) {
                self.new_game();
            }
            return Effect::Redraw;
        }
        if let Some(i) = self.tabs.iter().position(|t| t.contains(x, y)) {
            let draw3 = i == 1;
            if draw3 != self.next_draw3 {
                self.next_draw3 = draw3;
                let _ = kit::save_config("solitaire", if draw3 { "draw=3\n" } else { "draw=1\n" });
                if self.game.moves == 0 {
                    self.game.draw3 = draw3;
                } else {
                    self.status =
                        String::from(if draw3 { "The next game draws three." } else { "The next game draws one." });
                }
            }
            return Effect::Redraw;
        }
        self.held = None;
        // The pointer plays: the keys' outline goes until they're used.
        self.keys_used = false;
        let Some((pile, k)) = self.hit(x, y) else { return Effect::None };
        self.cursor = (pile, k);
        match pile {
            Pile::Stock => self.draw_stock(),
            _ if self.game.movable(pile, k) => {
                let a = match pile {
                    Pile::Tab(i) => self.layout.in_column(i, &self.game.table.tab[i], k),
                    Pile::Waste => {
                        let n = self.game.table.waste.len();
                        self.layout.in_waste(n, k, self.game.draw3)
                    }
                    p => self.layout.slot(p),
                };
                crate::trace!("solitaire: picked up {pile:?} from card {k} at {x} {y}");
                self.held = Some(Held {
                    from: pile,
                    index: k,
                    grab: (x - a.x, y - a.y),
                    at: (x, y),
                    moved: false,
                    by_keys: false,
                });
            }
            _ => {}
        }
        Effect::Redraw
    }

    fn double_click(&mut self, x: f32, y: f32) -> Effect {
        self.held = None;
        if let Some((pile, _)) = self.hit(x, y)
            && pile != Pile::Stock
        {
            self.send_home(pile);
            return Effect::Redraw;
        }
        self.click(x, y)
    }

    fn drag(&mut self, x: f32, y: f32) -> Effect {
        let Some(h) = self.held.as_mut().filter(|h| !h.by_keys) else { return Effect::None };
        h.at = (x, y);
        h.moved = true;
        Effect::Redraw
    }

    fn release(&mut self) -> Effect {
        let Some(h) = self.held.filter(|h| !h.by_keys) else { return Effect::None };
        self.held = None;
        if !h.moved {
            return Effect::Redraw;
        }
        let card = Area::new(h.at.0 - h.grab.0, h.at.1 - h.grab.1, self.layout.card.0, self.layout.card.1);
        crate::trace!("solitaire: dropped with the pointer at {} {}", h.at.0, h.at.1);
        match self.drop_target(card) {
            Some(to) => {
                if !self.try_play(h.from, h.index, to) {
                    crate::trace!("solitaire: {:?} can't go on {to:?}", h.from);
                }
            }
            None => crate::trace!("solitaire: dropped on no pile"),
        }
        Effect::Redraw
    }

    fn tick(&mut self, now: Now) -> bool {
        self.now = now.mono;
        if self.finishing {
            if self.game.finish_step() {
                self.moved();
                if self.game.won() {
                    self.finishing = false;
                }
                return true;
            }
            self.finishing = false;
        }
        self.started.is_some() && self.won_at.is_none()
    }

    fn wake(&self, now: Now) -> Option<i64> {
        if self.finishing {
            return Some(70);
        }
        // The clock's next second.
        (self.started.is_some() && self.won_at.is_none())
            .then(|| 1000 - (now.mono - self.started.unwrap_or(0)).rem_euclid(1000))
    }
}

pub fn main() -> i32 {
    let mut seed = [0u8; 8];
    let _ = slate_rt::process::random(&mut seed);
    let draw3 = kit::load_config("solitaire").is_some_and(|t| t.lines().any(|l| l.trim() == "draw=3"));
    let mut s = Solitaire::new(u64::from_le_bytes(seed), draw3);
    kit::run("solitaire", "solitaire", None, Hints { min: (560, 460), size: (820, 640) }, &mut s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(rank: u8, suit: u8) -> Card {
        Card { rank, suit, up: true }
    }

    #[test]
    fn the_deal() {
        let g = Game::deal(42, false);
        let t = &g.table;
        for i in 0..7 {
            assert_eq!(t.tab[i].len(), i + 1);
            assert!(t.tab[i].last().unwrap().up);
            assert!(t.tab[i][..i].iter().all(|c| !c.up));
        }
        assert_eq!(t.stock.len(), 24);
        // Every card once.
        let mut all: Vec<(u8, u8)> = t.stock.iter().chain(t.tab.iter().flatten()).map(|c| (c.suit, c.rank)).collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 52);
        // The same seed deals the same game; another doesn't.
        assert_eq!(Game::deal(42, false).table, g.table);
        assert_ne!(Game::deal(43, false).table, g.table);
    }

    #[test]
    fn the_rules() {
        let mut g = Game::deal(1, false);
        g.table = Table::default();
        g.table.tab[0] = alloc::vec![Card { up: false, ..card(5, 3) }, card(9, 0)];
        g.table.tab[1] = alloc::vec![card(10, 1)];
        g.table.tab[2] = Vec::new();
        g.table.tab[3] = alloc::vec![card(13, 2), card(12, 0), card(11, 2)];
        g.table.waste = alloc::vec![card(1, 1)];
        // Down in alternating colours: the black 9 on the red 10, and the
        // face-down card under it turns up.
        assert!(g.play(Pile::Tab(0), 1, Pile::Tab(1)));
        assert!(g.table.tab[0][0].up);
        // Not the same colour, not out of order.
        assert!(!g.play(Pile::Tab(0), 0, Pile::Tab(1)), "black 5 on black 9");
        // Only a King, or a run from one, into an empty column.
        assert!(!g.play(Pile::Tab(1), 1, Pile::Tab(2)));
        assert!(g.play(Pile::Tab(3), 0, Pile::Tab(2)));
        assert_eq!(g.table.tab[2].len(), 3);
        // Foundations: the Ace first, then the same suit up.
        assert_eq!(g.foundation_for(Pile::Waste), Some(Pile::Found(0)));
        assert!(g.play(Pile::Waste, 0, Pile::Found(0)));
        g.table.waste.push(card(2, 2));
        assert_eq!(g.foundation_for(Pile::Waste), None, "the 2 of diamonds isn't the hearts'");
        g.table.waste.push(card(2, 1));
        assert!(g.play(Pile::Waste, 1, Pile::Found(0)));
        // Undo puts it back.
        assert!(g.undo());
        assert_eq!(g.table.found[0].len(), 1);
    }

    #[test]
    fn the_stock() {
        let mut g = Game::deal(7, true);
        assert!(g.draw());
        assert_eq!((g.table.waste.len(), g.table.stock.len()), (3, 21));
        assert!(g.table.waste.iter().all(|c| c.up));
        while !g.table.stock.is_empty() {
            g.draw();
        }
        assert_eq!(g.table.waste.len(), 24);
        // The waste goes back, in the order it was turned.
        let first = g.table.waste[0];
        assert!(g.draw());
        assert_eq!((g.table.stock.len(), g.table.waste.len()), (24, 0));
        assert_eq!(g.table.stock.last().map(|c| (c.rank, c.suit)), Some((first.rank, first.suit)));
        assert!(g.table.stock.iter().all(|c| !c.up));
    }

    #[test]
    fn finishing_by_itself() {
        let mut g = Game::deal(3, false);
        g.table = Table::default();
        // Each suit's cards, the highest at the bottom, in its own column.
        for s in 0..4 {
            g.table.tab[usize::from(s)] = (1..=13).rev().map(|r| card(r, s)).collect();
        }
        assert!(g.finishable());
        let mut n = 0;
        while g.finish_step() {
            n += 1;
        }
        assert!(g.won() && n == 52);
    }

    #[test]
    fn by_pointer_and_keys() {
        let mut s = Solitaire::new(5, false);
        s.layout = Layout::of(Area::new(0.0, 0.0, 820.0, 640.0));
        // A known table: a red 7 on the first column, a black 8 on the
        // second.
        s.game.table.tab[0] = alloc::vec![card(7, 1)];
        s.game.table.tab[1] = alloc::vec![card(8, 0)];
        let from = s.layout.in_column(0, &s.game.table.tab[0], 0);
        let to = s.layout.in_column(1, &s.game.table.tab[1], 0);
        s.click(from.x + 10.0, from.y + 10.0);
        s.drag(to.x + 10.0, to.y + 30.0);
        s.release();
        assert_eq!(s.game.table.tab[1].len(), 2, "dragged onto the 8");
        assert_eq!(s.game.moves, 1);
        // Clicking the stock turns it.
        let st = s.layout.slot(Pile::Stock);
        let before = s.game.table.waste.len();
        s.click(st.x + 5.0, st.y + 5.0);
        assert_eq!(s.game.table.waste.len(), before + 1);
        // Keys: the 7 back (undo), then pick it up and put it on the 8.
        s.key(0, Some('z'), CTRL);
        s.key(0, Some('z'), CTRL);
        assert_eq!(s.game.table.tab[1].len(), 1);
        s.cursor = (Pile::Tab(0), 0);
        // The first key shows the cursor; the next acts.
        s.key(KEY_ENTER, None, 0);
        assert!(s.keys_used && s.held.is_none());
        s.key(KEY_ENTER, None, 0);
        s.key(KEY_RIGHT, None, 0);
        s.key(KEY_ENTER, None, 0);
        assert_eq!(s.game.table.tab[1].len(), 2, "moved by keys");
        // Drawing three next time.
        s.tabs = alloc::vec![Area::new(0.0, 0.0, 10.0, 10.0), Area::new(20.0, 0.0, 10.0, 10.0)];
        assert!(!s.next_draw3);
        s.click(25.0, 5.0);
        assert!(s.next_draw3 && s.status.contains("next game"));
    }
}
