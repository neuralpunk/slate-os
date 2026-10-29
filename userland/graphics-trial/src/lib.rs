// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-graphics-trial (ADR 0173): the first start after full graphics
//! is turned on asks, before anyone logs in, whether to keep it. A
//! dialog counts down [`SECONDS`]: Keep confirms the system (`slate-update
//! boot-ok`); Revert, Esc, or no answer takes AMD's firmware away again
//! (`quarry remove slate-firmware-gpu`, itself an update with a rollback)
//! and restarts on standard graphics. A screen that shows nothing can't
//! be kept by mistake: the time runs out. If the card didn't light at
//! all, it goes back at once. The boot menu's "Slate (standard
//! graphics)" entry is the way back when a start doesn't get this far.
//!
//! slinit runs it (`wait`, before the console's login); without the
//! broker's trial mark ([`MARK`]) it does nothing.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::vec::Vec;

use slate_rt::{fs, process};
use slate_ui::text::Style;
use slate_ui::ui::{Area, Event, Key, Ui, Variant};
use slate_ui::{Canvas, Color};

/// The broker's mark: full graphics on trial (slate-update's
/// `GRAPHICS_TRIAL`).
pub const MARK: &[u8] = b"/var/lib/slate/graphics-trial";

/// How long the question waits.
pub const SECONDS: u32 = 20;

/// The dialog's buttons (ids for the Ui's focus).
const KEEP: u32 = 1;
const REVERT: u32 = 2;

/// What the person decided (or the time did).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Keep,
    Revert,
}

/// The question: when it started (ms), which button has the focus (Revert
/// at first, so that Enter on a screen that can't be read goes back), the
/// buttons' places as last drawn.
#[derive(Clone, Debug)]
pub struct Trial {
    started: i64,
    focus: u32,
    buttons: [(u32, Area); 2],
}

impl Trial {
    pub fn new(now_ms: i64) -> Trial {
        Trial { started: now_ms, focus: REVERT, buttons: [(KEEP, Area::default()), (REVERT, Area::default())] }
    }

    /// Whole seconds left at `now_ms`.
    pub fn left(&self, now_ms: i64) -> u32 {
        let gone = ((now_ms - self.started).max(0) / 1000) as u32;
        SECONDS.saturating_sub(gone)
    }

    /// The decision at `now_ms`, if the time has run out.
    pub fn timed_out(&self, now_ms: i64) -> Option<Decision> {
        (self.left(now_ms) == 0).then_some(Decision::Revert)
    }

    /// An input event: the decision it makes, if any.
    pub fn handle(&mut self, ev: &Event) -> Option<Decision> {
        let pressed = |id| if id == KEEP { Decision::Keep } else { Decision::Revert };
        match ev {
            Event::Key(k, _) => match k {
                Key::Enter | Key::Space => Some(pressed(self.focus)),
                Key::Escape => Some(Decision::Revert),
                Key::Tab | Key::BackTab | Key::Left | Key::Right => {
                    self.focus = if self.focus == KEEP { REVERT } else { KEEP };
                    None
                }
                _ => None,
            },
            Event::PointerDown(x, y) => self
                .buttons
                .iter()
                .find(|(_, a)| *x >= a.x && *x < a.x + a.w && *y >= a.y && *y < a.y + a.h)
                .map(|(id, _)| pressed(*id)),
            _ => None,
        }
    }

    /// The dialog, centred, over the desktop colour, at `now_ms`.
    pub fn draw(&mut self, ui: &mut Ui<'_, '_>, size: (f32, f32), now_ms: i64) {
        let th = ui.theme;
        let (w, h) = size;
        ui.fill(Area { x: 0.0, y: 0.0, w, h }, 0.0, th.desktop);
        let (dw, dh) = (520.0f32.min(w - 32.0), 300.0);
        let d = Area { x: (w - dw) / 2.0, y: (h - dh) / 2.0, w: dw, h: dh };
        ui.fill(d, 12.0, th.window);
        ui.border(d, 12.0, 1.0, th.border);
        let (x, inner) = (d.x + 28.0, dw - 56.0);
        ui.heading(x, d.y + 24.0, "Keep full graphics?");
        let body = Style::new(&ui.fonts.regular, 15.0 * ui.scale, th.text_2);
        let lines = ui.wrap_lines(
            &ui.fonts.regular,
            15.0,
            "Your display now runs on SlateOS's driver with AMD's firmware. If it looks right, keep it. \
             If you don't answer, SlateOS goes back to its standard graphics and restarts.",
            inner,
        );
        let mut y = d.y + 92.0;
        for l in &lines {
            ui.text(&body, x, y, l);
            y += 22.0;
        }
        let left = self.left(now_ms);
        let count = Style::new(&ui.fonts.medium, 15.0 * ui.scale, th.ink);
        ui.text(&count, x, y + 14.0, &format!("Going back in {left} s"));
        let by = d.y + dh - 28.0 - 40.0;
        let keep_w = ui.button_width("Keep", Variant::Primary);
        let revert_w = ui.button_width("Revert", Variant::Secondary);
        let keep = Area { x: d.x + dw - 28.0 - keep_w, y: by, w: keep_w, h: 40.0 };
        let revert = Area { x: keep.x - 12.0 - revert_w, y: by, w: revert_w, h: 40.0 };
        ui.focus = Some(self.focus);
        ui.focus_visible = true;
        ui.button(REVERT, revert, "Revert", Variant::Secondary);
        ui.button(KEEP, keep, "Keep", Variant::Primary);
        // The pointer's coordinates are the Ui's logical ones.
        self.buttons = [(KEEP, keep), (REVERT, revert)];
    }
}

/// Run `argv`; its exit status.
fn run(argv: &[&[u8]]) -> i32 {
    let args: Vec<Vec<u8>> = argv.iter().map(|a| a.to_vec()).collect();
    match process::fork() {
        Ok(0) => {
            let e = process::execve(argv[0], &args, slate_rt::env::vars());
            slate_rt::eprintln!("slate-graphics-trial: {}: {e}", slate_rt::lossy(argv[0]));
            process::exit_now(127)
        }
        Ok(child) => process::wait(child, 0).map_or(1, |(_, s)| s),
        Err(_) => 1,
    }
}

fn now_ms() -> i64 {
    (slate_rt::time::monotonic_ns() / 1_000_000) as i64
}

/// Carry the decision out: the mark goes either way.
fn decide(d: Decision) -> i32 {
    let _ = fs::unlink(MARK);
    match d {
        Decision::Keep => {
            slate_rt::eprintln!("slate-graphics-trial: full graphics kept");
            run(&[b"/bin/slate-update", b"boot-ok"])
        }
        Decision::Revert => {
            slate_rt::eprintln!("slate-graphics-trial: back to standard graphics; restarting");
            let r = run(&[b"/bin/quarry", b"remove", b"slate-firmware-gpu"]);
            if r != 0 {
                // The system on trial isn't confirmed: a restart falls back
                // to the one before it, where there is one.
                slate_rt::eprintln!("slate-graphics-trial: quarry couldn't remove AMD's firmware ({r})");
            }
            fs::sync();
            let e = process::reboot(process::RB_AUTOBOOT);
            slate_rt::eprintln!("slate-graphics-trial: restarting failed ({e})");
            1
        }
    }
}

static FONTS: [&[u8]; 5] = [
    include_bytes!("../../../assets/fonts/HostGrotesk-400.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-500.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-600.ttf"),
    include_bytes!("../../../assets/fonts/HostGrotesk-800.ttf"),
    include_bytes!("../../../assets/fonts/DMMono-Regular.ttf"),
];

pub fn main() -> i32 {
    if !fs::exists(MARK) {
        return 0;
    }
    // The card didn't light: full graphics isn't working here.
    let lit = slate_sysinfo::graphics().iter().any(|(_, c)| c.contains("AMD's firmware"));
    if !lit {
        slate_rt::eprintln!("slate-graphics-trial: full graphics didn't start");
        return decide(Decision::Revert);
    }
    slate_rt::eprintln!(
        "slate-graphics-trial: keep full graphics? Keep on the screen within {SECONDS} s, or it goes back"
    );
    let Ok(mut display) = slate_display::kms::Display::open() else { return decide(Decision::Revert) };
    let Some(fonts) = slate_ui::theme::Fonts::new(FONTS) else { return decide(Decision::Revert) };
    let _ = display.double_buffer();
    let (w, h) = (display.width, display.height);
    let scale = if w >= 2560 { 2.0 } else { 1.0 };
    let mut canvas = Canvas::new(w, h, Color::rgb(0));
    let mut cache = slate_ui::text::GlyphCache::new();
    let mut inputs = slate_display::input::Inputs::new(w, h);
    let mut trial = Trial::new(now_ms());
    loop {
        {
            let mut ui = Ui::new(&mut canvas, &mut cache, &fonts, scale);
            // The whole screen, not the installer's centred window.
            ui.origin = (0.0, 0.0);
            trial.draw(&mut ui, (w as f32 / scale, h as f32 / scale), now_ms());
        }
        if inputs.pointer_seen {
            slate_ui::icon::pointer(&mut canvas, inputs.pointer.0, inputs.pointer.1, scale);
        }
        display.show(&canvas.pixels);
        for ev in inputs.wait(250) {
            let ev = match ev {
                Event::PointerDown(x, y) => Event::PointerDown(x / scale, y / scale),
                e => e,
            };
            if let Some(d) = trial.handle(&ev) {
                drop(display);
                return decide(d);
            }
        }
        if let Some(d) = trial.timed_out(now_ms()) {
            drop(display);
            return decide(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slate_ui::ui::Mods;

    fn key(k: Key) -> Event {
        Event::Key(k, Mods::default())
    }

    #[test]
    fn the_time_runs_out_to_standard_graphics() {
        let t = Trial::new(1000);
        assert_eq!(t.left(1000), 20);
        assert_eq!(t.left(10_999), 11);
        assert_eq!(t.timed_out(20_999), None);
        assert_eq!(t.timed_out(21_000), Some(Decision::Revert));
    }

    #[test]
    fn enter_reverts_until_keep_is_chosen() {
        let mut t = Trial::new(0);
        assert_eq!(t.handle(&key(Key::Enter)), Some(Decision::Revert));
        assert_eq!(t.handle(&key(Key::Tab)), None);
        assert_eq!(t.handle(&key(Key::Enter)), Some(Decision::Keep));
        assert_eq!(t.handle(&key(Key::Escape)), Some(Decision::Revert));
        assert_eq!(t.handle(&key(Key::Char('k'))), None);
    }

    #[test]
    fn the_buttons_as_drawn() {
        let mut t = Trial::new(0);
        t.buttons = [
            (KEEP, Area { x: 100.0, y: 50.0, w: 80.0, h: 40.0 }),
            (REVERT, Area { x: 10.0, y: 50.0, w: 80.0, h: 40.0 }),
        ];
        assert_eq!(t.handle(&Event::PointerDown(120.0, 60.0)), Some(Decision::Keep));
        assert_eq!(t.handle(&Event::PointerDown(20.0, 60.0)), Some(Decision::Revert));
        assert_eq!(t.handle(&Event::PointerDown(95.0, 60.0)), None);
    }
}
