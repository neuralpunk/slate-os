// SPDX-License-Identifier: MIT OR Apache-2.0

//! Calculator (ADR 0104): basic and scientific, driven by the keyboard
//! as much as by its buttons. What is typed is an expression
//! ([`crate::expr`]), shown as typed with its value beneath it while
//! it is being written; Enter gives the answer, and the last few sums
//! stay above it.
//!
//! Keys: digits, `. + - * / ^ ( ) ! %` and function names type
//! themselves; Enter or `=` works it out; Backspace takes the last
//! character back, Esc clears; up and down bring back earlier sums;
//! Tab switches basic and scientific; ctrl + d switches degrees and
//! radians; ctrl + b shows whole answers in base 16, 8, 2 or 10; ctrl +
//! c copies the answer, ctrl + v pastes. The memory: ctrl + m adds the
//! answer to it (with shift, takes it away), ctrl + r types `mem`, ctrl
//! + l clears it. Answers show their digits in threes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{KEY_BACKSPACE, KEY_DELETE, KEY_DOWN, KEY_ENTER, KEY_ESC, KEY_KPENTER, KEY_TAB, KEY_UP};
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use crate::expr::{self, Angle, Error};
use crate::kit::{self, App, Effect, Hints};

/// A button's action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    Type(&'static str),
    Clear,
    Back,
    Equals,
    Angle,
    /// 1/x: the whole expression under one.
    Inverse,
    /// The next base answers are shown in.
    Base,
    MemClear,
    MemRecall,
    MemAdd,
    MemTake,
}

#[derive(Clone, Copy, Debug)]
struct Btn {
    label: &'static str,
    act: Act,
}

const fn t(label: &'static str, text: &'static str) -> Btn {
    Btn { label, act: Act::Type(text) }
}

const ROWS: usize = 6;

const BASIC: [[Btn; 4]; ROWS] = [
    [
        Btn { label: "MC", act: Act::MemClear },
        Btn { label: "MR", act: Act::MemRecall },
        Btn { label: "M+", act: Act::MemAdd },
        Btn { label: "M−", act: Act::MemTake },
    ],
    [Btn { label: "C", act: Act::Clear }, t("(", "("), t(")", ")"), t("÷", "÷")],
    [t("7", "7"), t("8", "8"), t("9", "9"), t("×", "×")],
    [t("4", "4"), t("5", "5"), t("6", "6"), t("−", "−")],
    [t("1", "1"), t("2", "2"), t("3", "3"), t("+", "+")],
    [t("0", "0"), t(".", "."), Btn { label: "⌫", act: Act::Back }, Btn { label: "=", act: Act::Equals }],
];

const SCIENTIFIC: [[Btn; 4]; ROWS] = [
    [t("sinh", "sinh("), t("cosh", "cosh("), t("tanh", "tanh("), Btn { label: "dec", act: Act::Base }],
    [Btn { label: "deg", act: Act::Angle }, t("π", "π"), t("e", "e"), t("x^y", "^")],
    [t("sin", "sin("), t("cos", "cos("), t("tan", "tan("), t("n!", "!")],
    [t("asin", "asin("), t("acos", "acos("), t("atan", "atan("), t("%", "%")],
    [t("ln", "ln("), t("log", "log("), t("√", "√("), t("x²", "^2")],
    [t("exp", "exp("), t("abs", "abs("), t("ans", "ans"), Btn { label: "1/x", act: Act::Inverse }],
];

/// How many sums the calculator remembers, and shows above the answer.
const HISTORY: usize = 50;
const SHOWN: usize = 2;
/// The longest expression it takes.
const MAX: usize = 200;

pub const BASIC_HINTS: Hints = Hints { min: (300, 510), size: (340, 590) };
pub const SCIENTIFIC_HINTS: Hints = Hints { min: (560, 510), size: (640, 590) };

#[derive(Debug)]
pub struct Calc {
    pub expr: String,
    /// The answer to the expression shown, once Enter was pressed (or
    /// why there is none).
    pub done: Option<Result<f64, Error>>,
    pub ans: f64,
    /// Earlier sums, oldest first: (expression, answer).
    pub history: Vec<(String, String)>,
    /// Which earlier sum up and down have brought back.
    recall: Option<usize>,
    pub scientific: bool,
    pub angle: Angle,
    /// The base whole answers are shown in: 10, 16, 8 or 2.
    pub base: u32,
    /// The memory, once something was put in it.
    pub memory: Option<f64>,
    hits: Vec<(Area, Act)>,
    mode_tabs: Vec<Area>,
    /// The size hints to send (after Tab or a click on the mode).
    pub hints: Option<Hints>,
}

impl Default for Calc {
    fn default() -> Self {
        Calc {
            expr: String::new(),
            done: None,
            ans: 0.0,
            history: Vec::new(),
            recall: None,
            scientific: false,
            angle: Angle::Degrees,
            base: 10,
            memory: None,
            hits: Vec::new(),
            mode_tabs: Vec::new(),
            hints: None,
        }
    }
}

/// What a typed character stands for in the expression (the display's
/// symbols), if it belongs in one.
fn symbol(c: char) -> Option<char> {
    Some(match c {
        '*' => '×',
        '/' => '÷',
        '-' => '−',
        '0'..='9' | '.' | '+' | '^' | '(' | ')' | '!' | '%' | '×' | '÷' | '−' | 'π' | '√' | ' ' => c,
        c if c.is_ascii_alphabetic() => c.to_ascii_lowercase(),
        _ => return None,
    })
}

impl Calc {
    /// The value of what is typed, if it has one.
    pub fn preview(&self) -> Result<f64, Error> {
        expr::eval_with(&self.expr, self.ans, self.memory.unwrap_or(0.0), self.angle)
    }

    fn typing(&mut self, text: &str) {
        // After an answer, an operator goes on from it and anything else
        // starts afresh; after an error, typing mends the expression.
        if let Some(done) = self.done.take()
            && done.is_ok()
        {
            let first = text.chars().next().unwrap_or(' ');
            self.expr = if matches!(first, '+' | '−' | '×' | '÷' | '^' | '!' | '%') {
                String::from("ans")
            } else {
                String::new()
            };
        }
        self.recall = None;
        for c in text.chars() {
            if self.expr.chars().count() < MAX {
                self.expr.push(c);
            }
        }
    }

    fn act(&mut self, a: Act) -> Effect {
        match a {
            Act::Type(s) => self.typing(s),
            Act::Clear => {
                self.expr.clear();
                self.done = None;
                self.recall = None;
            }
            Act::Back => {
                self.done = None;
                self.expr.pop();
            }
            Act::Equals => self.equals(),
            Act::Angle => {
                self.angle = if self.angle == Angle::Degrees { Angle::Radians } else { Angle::Degrees };
            }
            Act::Base => {
                self.base = match self.base {
                    10 => 16,
                    16 => 8,
                    8 => 2,
                    _ => 10,
                };
                crate::trace!(
                    "calculator: base {}: {}",
                    self.base,
                    self.answer_text().map_or(String::new(), |v| self.shown(&v))
                );
            }
            Act::MemClear => self.memory = None,
            Act::MemRecall if self.memory.is_some() => self.typing("mem"),
            Act::MemRecall => return Effect::None,
            Act::MemAdd | Act::MemTake => {
                let Some(v) = self.value() else { return Effect::None };
                let v = if a == Act::MemAdd { v } else { -v };
                let m = self.memory.unwrap_or(0.0) + v;
                self.memory = Some(m);
                crate::trace!("calculator: memory {}", expr::format(m));
            }
            Act::Inverse => {
                let inner = if matches!(self.done, Some(Ok(_))) || self.expr.is_empty() {
                    String::from("ans")
                } else {
                    core::mem::take(&mut self.expr)
                };
                self.done = None;
                self.expr = alloc::format!("1÷({inner})");
            }
        }
        Effect::Redraw
    }

    fn equals(&mut self) {
        if self.done.is_some() || self.expr.trim().is_empty() {
            return;
        }
        let r = self.preview();
        // In ASCII: the serial console a scenario reads is bytes.
        let ascii: String = self
            .expr
            .chars()
            .map(|c| match c {
                '×' => '*',
                '÷' => '/',
                '−' => '-',
                c => c,
            })
            .collect();
        match r {
            Ok(v) => crate::trace!("calculator: {ascii} = {}", expr::format(v)),
            Err(e) => crate::trace!("calculator: {ascii}: {e:?}"),
        }
        if let Ok(v) = r {
            self.ans = v;
            self.history.push((self.expr.clone(), expr::format(v)));
            if self.history.len() > HISTORY {
                self.history.remove(0);
            }
        }
        self.done = Some(r);
    }

    fn switch_mode(&mut self) -> Effect {
        self.scientific = !self.scientific;
        self.hints = Some(if self.scientific { SCIENTIFIC_HINTS } else { BASIC_HINTS });
        Effect::Redraw
    }

    /// The answer: the one given, else the value of what is typed.
    fn value(&self) -> Option<f64> {
        match self.done {
            Some(Ok(v)) => Some(v),
            Some(Err(_)) => None,
            None => self.preview().ok(),
        }
    }

    /// The answer as text, for copying (in the base shown, which pastes
    /// back).
    pub fn answer_text(&self) -> Option<String> {
        let v = self.value()?;
        Some(expr::format_base(v, self.base).unwrap_or_else(|| expr::format(v)))
    }

    /// An answer's text as the display shows it: in threes, or in the
    /// base chosen.
    fn shown(&self, text: &str) -> String {
        if text.contains(['x', 'o', 'b']) { String::from(text) } else { expr::grouped(text) }
    }

    /// `v` for the display.
    fn display(&self, v: f64) -> String {
        expr::format_base(v, self.base).unwrap_or_else(|| expr::grouped(&expr::format(v)))
    }
}

impl App for Calc {
    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        self.hits.clear();
        let pad = 16.0;
        let x = a.x + pad;
        let w = a.w - 2.0 * pad;
        // The mode, and the angle unit in scientific mode.
        self.mode_tabs =
            kit::tabs(p, pal, f, x - 4.0, a.y + 12.0, &["basic", "scientific"], usize::from(self.scientific));
        {
            // The memory, the base and (scientific) the angle unit.
            let unit = p.style(&f.mono, 11.0, pal.muted);
            let mut words: Vec<&str> = Vec::new();
            if self.memory.is_some() {
                words.push("M");
            }
            match self.base {
                16 => words.push("hex"),
                8 => words.push("oct"),
                2 => words.push("bin"),
                _ => {}
            }
            if self.scientific {
                words.push(if self.angle == Angle::Degrees { "degrees" } else { "radians" });
            }
            let text = words.join(" · ");
            let tw = p.measure(&unit, &text);
            p.line(&unit, x + w - tw, a.y + 17.0, 20.0, &text);
        }
        // The display: earlier sums, what is typed, and its value.
        let display = Area::new(x, a.y + 52.0, w, 128.0);
        p.fill(display, 10.0, pal.well);
        let right = display.x + display.w - 16.0;
        let old = p.style(&f.mono, 12.0, pal.muted);
        let mut y = display.y + 10.0;
        for (e, v) in self.history.iter().rev().take(SHOWN).collect::<Vec<_>>().into_iter().rev() {
            let line = alloc::format!("{e} = {}", self.shown(v));
            let line = fit(p, &old, &line, display.w - 32.0);
            let lw = p.measure(&old, &line);
            p.line(&old, right - lw, y, 18.0, &line);
            y += 18.0;
        }
        let typed = p.style(&f.mono, 16.0, if self.done.is_some() { pal.text_3 } else { pal.text_1 });
        let shown = if self.expr.is_empty() && self.done.is_none() { "0".to_string() } else { self.expr.clone() };
        let shown = fit(p, &typed, &shown, display.w - 32.0);
        let tw = p.measure(&typed, &shown);
        let ty = display.y + 50.0;
        p.line(&typed, right - tw, ty, 24.0, &shown);
        let big = p.style(&f.mono_medium, 30.0, pal.chalk);
        let small = p.style(&f.mono, 15.0, pal.muted);
        let warn = p.style(&f.regular, 14.0, pal.text_2);
        let (style, text) = match self.done {
            Some(Ok(v)) => (&big, self.display(v)),
            Some(Err(e)) => (&warn, e.text().to_string()),
            None => match self.preview() {
                Ok(v) if !self.expr.is_empty() => (&small, alloc::format!("= {}", self.display(v))),
                _ => (&small, String::new()),
            },
        };
        let text = fit(p, style, &text, display.w - 32.0);
        let vw = p.measure(style, &text);
        p.line(style, right - vw, display.y + 80.0, 40.0, &text);
        // The buttons.
        let top = display.y + display.h + 14.0;
        let bottom = a.y + a.h - 40.0;
        let gap = 8.0;
        let cols = if self.scientific { 8 } else { 4 };
        let bw = (w - gap * (cols as f32 - 1.0)) / cols as f32;
        let bh = ((bottom - top - gap * (ROWS as f32 - 1.0)) / ROWS as f32).max(24.0);
        let mut grids: Vec<(&[[Btn; 4]; ROWS], f32)> = Vec::new();
        if self.scientific {
            grids.push((&SCIENTIFIC, x));
            grids.push((&BASIC, x + 4.0 * (bw + gap)));
        } else {
            grids.push((&BASIC, x));
        }
        for (grid, gx) in grids {
            for (r, row) in grid.iter().enumerate() {
                for (c, b) in row.iter().enumerate() {
                    let area = Area::new(gx + c as f32 * (bw + gap), top + r as f32 * (bh + gap), bw, bh);
                    let label = match b.act {
                        Act::Angle if self.angle == Angle::Radians => "rad",
                        Act::Base => match self.base {
                            16 => "hex",
                            8 => "oct",
                            2 => "bin",
                            _ => "dec",
                        },
                        _ => b.label,
                    };
                    kit::button(p, pal, f, area, label, b.act == Act::Equals, false);
                    self.hits.push((area, b.act));
                }
            }
        }
        let hint: &[(&str, &str)] = if self.scientific {
            &[("enter", "answer"), ("esc", "clear"), ("tab", "basic"), ("ctrl d", "deg/rad"), ("ctrl b", "base")]
        } else {
            &[("enter", "answer"), ("esc", "clear"), ("tab", "scientific")]
        };
        kit::hints(p, pal, f, a, hint);
    }

    fn take_hints(&mut self) -> Option<Hints> {
        self.hints.take()
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        let ctrl = mods & CTRL != 0;
        let shortcut = mods & (CTRL | ALT | LOGO) != 0;
        match (code, ch.map(|c| c.to_ascii_lowercase())) {
            (_, Some('c')) if ctrl => return self.answer_text().map_or(Effect::None, Effect::Copy),
            (_, Some('v')) if ctrl => return Effect::Paste,
            (_, Some('d')) if ctrl => return self.act(Act::Angle),
            (_, Some('b')) if ctrl => return self.act(Act::Base),
            (_, Some('m')) if ctrl && mods & SHIFT != 0 => return self.act(Act::MemTake),
            (_, Some('m')) if ctrl => return self.act(Act::MemAdd),
            (_, Some('r')) if ctrl => return self.act(Act::MemRecall),
            (_, Some('l')) if ctrl => return self.act(Act::MemClear),
            _ if shortcut => return Effect::None,
            (KEY_ENTER | KEY_KPENTER, _) | (_, Some('=')) => return self.act(Act::Equals),
            (KEY_BACKSPACE, _) => return self.act(Act::Back),
            (KEY_ESC | KEY_DELETE, _) => return self.act(Act::Clear),
            (KEY_TAB, _) => return self.switch_mode(),
            (KEY_UP | KEY_DOWN, _) => {
                if self.history.is_empty() {
                    return Effect::None;
                }
                let last = self.history.len() - 1;
                let at = match (self.recall, code == KEY_UP) {
                    (None, true) => Some(last),
                    (None, false) => None,
                    (Some(i), true) => Some(i.saturating_sub(1)),
                    (Some(i), false) if i < last => Some(i + 1),
                    (Some(_), false) => None,
                };
                self.recall = at;
                self.done = None;
                self.expr = at.map_or_else(String::new, |i| self.history[i].0.clone());
                return Effect::Redraw;
            }
            _ => {}
        }
        match ch.and_then(symbol) {
            Some(c) => {
                let mut b = [0u8; 4];
                self.typing(c.encode_utf8(&mut b));
                Effect::Redraw
            }
            None => Effect::None,
        }
    }

    fn click(&mut self, x: f32, y: f32) -> Effect {
        if let Some(i) = self.mode_tabs.iter().position(|a| a.contains(x, y)) {
            return if (i == 1) != self.scientific { self.switch_mode() } else { Effect::None };
        }
        match self.hits.iter().find(|(a, _)| a.contains(x, y)) {
            Some(&(_, act)) => self.act(act),
            None => Effect::None,
        }
    }

    fn paste(&mut self, text: &str) -> Effect {
        let clean: String = text.chars().filter_map(symbol).collect();
        if clean.is_empty() {
            return Effect::None;
        }
        self.typing(&clean);
        Effect::Redraw
    }
}

/// `s` cut from the left to fit `max` (the end of a long expression is
/// what matters), with an ellipsis.
fn fit(p: &Painter<'_>, style: &slate_ui::text::Style<'_, '_>, s: &str, max: f32) -> String {
    if p.measure(style, s) <= max {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    for start in 1..chars.len() {
        let t: String = core::iter::once('…').chain(chars[start..].iter().copied()).collect();
        if p.measure(style, &t) <= max {
            return t;
        }
    }
    String::new()
}

pub fn main() -> i32 {
    let mut c = Calc::default();
    kit::run("calculator", "calculator", None, BASIC_HINTS, &mut c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(c: &mut Calc, s: &str) {
        for ch in s.chars() {
            match ch {
                '\n' => c.key(KEY_ENTER, None, 0),
                _ => c.key(0, Some(ch), 0),
            };
        }
    }

    #[test]
    fn typing_and_answers() {
        let mut c = Calc::default();
        typed(&mut c, "12*(3+4");
        assert_eq!(c.expr, "12×(3+4");
        assert_eq!(c.preview(), Ok(84.0));
        typed(&mut c, "\n");
        assert_eq!((c.done, c.ans), (Some(Ok(84.0)), 84.0));
        assert_eq!(c.history.last().map(|h| h.1.as_str()), Some("84"));
        // An operator goes on from the answer; a digit starts afresh.
        typed(&mut c, "/2\n");
        assert_eq!((c.expr.as_str(), c.done), ("ans÷2", Some(Ok(42.0))));
        typed(&mut c, "7");
        assert_eq!((c.expr.as_str(), c.done), ("7", None));
        // Backspace, Esc, and the history.
        c.key(KEY_BACKSPACE, None, 0);
        assert!(c.expr.is_empty());
        c.key(KEY_UP, None, 0);
        assert_eq!(c.expr, "ans÷2");
        c.key(KEY_UP, None, 0);
        assert_eq!(c.expr, "12×(3+4");
        c.key(KEY_DOWN, None, 0);
        c.key(KEY_DOWN, None, 0);
        assert!(c.expr.is_empty());
        typed(&mut c, "1/0\n");
        assert_eq!(c.done, Some(Err(Error::DivideByZero)));
        c.key(KEY_ESC, None, 0);
        assert!(c.expr.is_empty() && c.done.is_none());
    }

    #[test]
    fn scientific_keys_and_the_clipboard() {
        let mut c = Calc::default();
        assert_eq!(c.key(KEY_TAB, None, 0), Effect::Redraw);
        assert!(c.scientific && c.hints.is_some());
        c.act(Act::Type("sin("));
        typed(&mut c, "30)\n");
        assert_eq!(c.done, Some(Ok(0.5)));
        assert_eq!(c.key(0, Some('c'), CTRL), Effect::Copy("0.5".into()));
        c.key(0, Some('d'), CTRL);
        assert_eq!(c.angle, Angle::Radians);
        c.act(Act::Clear);
        typed(&mut c, "4");
        c.act(Act::Inverse);
        assert_eq!(c.expr, "1÷(4)");
        assert_eq!(c.paste("2 * 3\nfoo"), Effect::Redraw);
        assert_eq!(c.expr, "1÷(4)2 × 3foo");
        assert_eq!(c.key(0, Some('v'), CTRL), Effect::Paste);
    }

    #[test]
    fn memory_and_bases() {
        let mut c = Calc::default();
        typed(&mut c, "6*7\n");
        c.key(0, Some('m'), CTRL);
        assert_eq!(c.memory, Some(42.0));
        typed(&mut c, "2\n");
        c.key(0, Some('m'), CTRL | SHIFT);
        assert_eq!(c.memory, Some(40.0));
        c.key(0, Some('r'), CTRL);
        typed(&mut c, "/8\n");
        assert_eq!((c.expr.as_str(), c.done), ("mem÷8", Some(Ok(5.0))));
        c.key(0, Some('l'), CTRL);
        assert_eq!(c.memory, None);
        assert_eq!(c.act(Act::MemRecall), Effect::None, "nothing to recall");
        // Bases: whole answers in hex, octal and binary; copied as shown.
        typed(&mut c, "255\n");
        c.key(0, Some('b'), CTRL);
        assert_eq!((c.base, c.display(255.0)), (16, String::from("0xFF")));
        assert_eq!(c.key(0, Some('c'), CTRL), Effect::Copy("0xFF".into()));
        c.key(0, Some('b'), CTRL);
        c.key(0, Some('b'), CTRL);
        assert_eq!(c.display(5.0), "0b101");
        assert_eq!(c.display(2.5), "2.5", "not whole: in tens");
        c.key(0, Some('b'), CTRL);
        assert_eq!((c.base, c.display(1234567.0)), (10, String::from("1,234,567")));
        assert_eq!(c.key(0, Some('c'), CTRL), Effect::Copy("255".into()));
    }
}
