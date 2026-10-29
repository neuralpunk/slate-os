// SPDX-License-Identifier: MIT OR Apache-2.0

//! Motion (docs/design/WM_STYLE.md §2, ADR 0038): the focus border cross-fades in
//! 120 ms; the launcher and dialogs fade and rise 6 px in 140 ms and fade
//! out in 100 ms; windows fade in as they open or come back, and fade out
//! as they minimise (140 ms); a workspace switch slides the whole
//! workspace sideways in 160 ms (ADR 0039); a title bar button's hover
//! fill fades in over 80 ms (ADR 0124). Everything eases out. With
//! reduced motion, every duration is zero.
//!
//! Times are milliseconds of the monotonic clock; the session draws frames
//! only while [`Motion::active`].

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::wm::WinId;

pub const FOCUS_MS: i64 = 120;
pub const OVERLAY_IN_MS: i64 = 140;
pub const OVERLAY_OUT_MS: i64 = 100;
pub const WINDOW_MS: i64 = 140;
pub const SLIDE_MS: i64 = 160;
pub const HOVER_MS: i64 = 80;
/// How far the launcher and dialogs rise as they appear, and windows as
/// they open (logical pixels).
pub const RISE: f32 = 6.0;

/// The ease-out curve (a cubic).
pub fn ease_out(t: f32) -> f32 {
    let u = 1.0 - t.clamp(0.0, 1.0);
    1.0 - u * u * u
}

/// A value going from `from` to `to`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tween {
    pub start: i64,
    pub dur: i64,
    pub from: f32,
    pub to: f32,
}

impl Tween {
    pub fn value(&self, now: i64) -> f32 {
        if self.dur <= 0 || now >= self.start + self.dur {
            return self.to;
        }
        let t = (now - self.start).max(0) as f32 / self.dur as f32;
        self.from + (self.to - self.from) * ease_out(t)
    }

    pub fn done(&self, now: i64) -> bool {
        now >= self.start + self.dur
    }
}

/// What a window is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fade {
    /// Opening or coming back: fading in, settling down from 6 px above.
    In,
    /// Minimising: fading out, sinking; minimised when done.
    Out,
}

/// How to draw a window now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Look {
    /// 0 unfocused, 1 focused (the border's mix).
    pub focus: f32,
    pub opacity: f32,
    /// Shift down, logical pixels.
    pub dy: f32,
}

#[derive(Clone, Debug, Default)]
pub struct Motion {
    pub reduced: bool,
    focused: Option<WinId>,
    focus: BTreeMap<WinId, Tween>,
    windows: BTreeMap<WinId, (Tween, Fade)>,
    overlay: Option<Tween>,
    /// A workspace switch: the workspace left, and the slide's progress.
    slide: Option<(usize, Tween)>,
    /// The hovered title bar button's fill fading in.
    hover: Option<Tween>,
}

/// How a workspace switch is drawn now: the workspace being left, and
/// how far the shown one is shifted (logical pixels; the one left sits a
/// screen's width further on that side).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Slide {
    pub from: usize,
    pub shift: f32,
    /// +1 when the new workspace comes in from the right.
    pub dir: f32,
}

impl Motion {
    pub fn new(reduced: bool) -> Motion {
        Motion { reduced, ..Motion::default() }
    }

    fn dur(&self, ms: i64) -> i64 {
        if self.reduced { 0 } else { ms }
    }

    /// The focus moved: the old window's border fades down, the new one's
    /// up, each from where it is now.
    pub fn focus(&mut self, now_focused: Option<WinId>, now: i64) {
        if now_focused == self.focused {
            return;
        }
        let d = self.dur(FOCUS_MS);
        for (id, to) in [(self.focused, 0.0), (now_focused, 1.0)] {
            let Some(id) = id else { continue };
            let from = self.focus_of(id, now);
            self.focus.insert(id, Tween { start: now, dur: d, from, to });
        }
        self.focused = now_focused;
    }

    fn focus_of(&self, id: WinId, now: i64) -> f32 {
        match self.focus.get(&id) {
            Some(t) => t.value(now),
            None => f32::from(u8::from(self.focused == Some(id))),
        }
    }

    /// A window opened or came back.
    pub fn fade_in(&mut self, id: WinId, now: i64) {
        let d = self.dur(WINDOW_MS);
        self.windows.insert(id, (Tween { start: now, dur: d, from: 0.0, to: 1.0 }, Fade::In));
    }

    /// A window starts minimising; [`Motion::minimised`] says when it may
    /// be hidden.
    pub fn fade_out(&mut self, id: WinId, now: i64) {
        let d = self.dur(WINDOW_MS);
        self.windows.insert(id, (Tween { start: now, dur: d, from: 1.0, to: 0.0 }, Fade::Out));
    }

    /// Whether `id` is fading out.
    pub fn leaving(&self, id: WinId) -> bool {
        self.windows.get(&id).is_some_and(|w| w.1 == Fade::Out)
    }

    /// The windows whose fade-out has finished (to minimise now); forgets
    /// finished fades.
    pub fn minimised(&mut self, now: i64) -> Vec<WinId> {
        let out: Vec<WinId> =
            self.windows.iter().filter(|(_, (t, f))| *f == Fade::Out && t.done(now)).map(|(id, _)| *id).collect();
        self.windows.retain(|_, (t, _)| !t.done(now));
        self.focus.retain(|_, t| !t.done(now));
        out
    }

    pub fn look(&self, id: WinId, now: i64) -> Look {
        let focus = self.focus_of(id, now);
        match self.windows.get(&id) {
            Some((t, Fade::In)) => {
                let o = t.value(now);
                Look { focus, opacity: o, dy: -(1.0 - o) * RISE }
            }
            Some((t, Fade::Out)) => {
                let o = t.value(now);
                Look { focus, opacity: o, dy: (1.0 - o) * 2.0 * RISE }
            }
            None => Look { focus, opacity: 1.0, dy: 0.0 },
        }
    }

    /// The launcher or a dialog appears.
    pub fn overlay_in(&mut self, now: i64) {
        let from = self.overlay.map_or(0.0, |t| t.value(now));
        self.overlay = Some(Tween { start: now, dur: self.dur(OVERLAY_IN_MS), from, to: 1.0 });
    }

    /// It goes: fading out from where it is.
    pub fn overlay_out(&mut self, now: i64) {
        let from = self.overlay.map_or(1.0, |t| t.value(now));
        self.overlay = Some(Tween { start: now, dur: self.dur(OVERLAY_OUT_MS), from, to: 0.0 });
    }

    /// The overlay's opacity now, None when gone.
    pub fn overlay(&self, now: i64) -> Option<f32> {
        let t = self.overlay?;
        let v = t.value(now);
        (t.to > 0.0 || v > 0.0).then_some(v)
    }

    /// Switched from workspace `from` to `to`: slide.
    pub fn switch(&mut self, from: usize, to: usize, now: i64) {
        if from != to {
            let dir = if to > from { 1.0 } else { -1.0 };
            self.slide = Some((from, Tween { start: now, dur: self.dur(SLIDE_MS), from: dir, to: 0.0 }));
        }
    }

    /// The slide now, on a screen `width` wide; None when still.
    pub fn slide(&self, now: i64, width: f32) -> Option<Slide> {
        let (from, t) = self.slide?;
        if t.done(now) {
            return None;
        }
        Some(Slide { from, shift: t.value(now) * width, dir: t.from })
    }

    /// The pointer came over a title bar button: its fill fades in.
    pub fn hover_in(&mut self, now: i64) {
        self.hover = Some(Tween { start: now, dur: self.dur(HOVER_MS), from: 0.0, to: 1.0 });
    }

    /// How far the hover fill has faded in (1 when settled).
    pub fn hover(&self, now: i64) -> f32 {
        self.hover.map_or(1.0, |t| t.value(now))
    }

    /// Whether the hover fill is still fading in. Apart from
    /// [`Motion::active`]: only the title bar is drawn for it, not the
    /// whole screen.
    pub fn hovering(&self, now: i64) -> bool {
        self.hover.is_some_and(|t| !t.done(now))
    }

    /// Whether the overlay is fading and nothing else moves: what is under
    /// it stays as it was drawn (M32 phase 2).
    pub fn only_overlay(&self, now: i64) -> bool {
        self.overlay.is_some_and(|t| !t.done(now))
            && !self.focus.values().any(|t| !t.done(now))
            && !self.windows.values().any(|(t, _)| !t.done(now))
            && !self.slide.is_some_and(|(_, t)| !t.done(now))
    }

    /// Whether anything is moving (the session draws frames until not).
    pub fn active(&self, now: i64) -> bool {
        self.focus.values().any(|t| !t.done(now))
            || self.windows.values().any(|(t, _)| !t.done(now))
            || self.overlay.is_some_and(|t| !t.done(now))
            || self.slide.is_some_and(|(_, t)| !t.done(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easing() {
        assert_eq!(ease_out(0.0), 0.0);
        assert_eq!(ease_out(1.0), 1.0);
        assert!(ease_out(0.5) > 0.5);
        let t = Tween { start: 100, dur: 100, from: 0.0, to: 1.0 };
        assert_eq!(t.value(50), 0.0);
        assert_eq!(t.value(250), 1.0);
        assert!(!t.done(150) && t.done(200));
    }

    #[test]
    fn focus_and_windows() {
        let mut m = Motion::new(false);
        m.focus(Some(1), 0);
        assert!(m.active(60));
        assert!(m.look(1, 60).focus > 0.0 && m.look(1, 60).focus < 1.0);
        assert_eq!(m.look(1, 200).focus, 1.0);
        m.focus(Some(2), 200);
        assert!(m.look(1, 260).focus < 1.0 && m.look(2, 260).focus > 0.0);
        m.fade_in(3, 300);
        assert!(m.look(3, 310).opacity < 0.5 && m.look(3, 310).dy < 0.0);
        m.fade_out(2, 400);
        assert!(m.leaving(2));
        assert!(m.minimised(450).is_empty());
        assert_eq!(m.minimised(600), alloc::vec![2]);
        assert!(!m.active(600));
        m.overlay_in(700);
        assert!(m.overlay(710).is_some_and(|o| o < 1.0));
        m.overlay_out(900);
        assert!(m.overlay(950).is_some_and(|o| o < 1.0));
        assert_eq!(m.overlay(1100), None);
        // To workspace 3 from 1: the new one comes in from the right.
        m.switch(0, 2, 2000);
        let s = m.slide(2080, 1000.0).unwrap();
        assert!(s.from == 0 && s.dir == 1.0 && s.shift > 0.0 && s.shift < 1000.0);
        assert_eq!(m.slide(2200, 1000.0), None);
        assert!(!m.active(2200));
    }

    #[test]
    fn reduced_motion_is_instant() {
        let mut m = Motion::new(true);
        m.focus(Some(1), 0);
        m.fade_in(1, 0);
        m.overlay_in(0);
        assert!(!m.active(0));
        assert_eq!(m.look(1, 0), Look { focus: 1.0, opacity: 1.0, dy: 0.0 });
        assert_eq!(m.overlay(0), Some(1.0));
        m.switch(0, 1, 0);
        assert_eq!(m.slide(0, 1000.0), None);
        m.hover_in(0);
        assert!(!m.hovering(0));
        assert_eq!(m.hover(0), 1.0);
    }

    #[test]
    fn hover_fades_in() {
        let mut m = Motion::new(false);
        assert_eq!(m.hover(0), 1.0);
        m.hover_in(1000);
        assert_eq!(m.hover(1000), 0.0);
        assert!(m.hovering(1040) && m.hover(1040) > 0.0 && m.hover(1040) < 1.0);
        assert!(!m.hovering(1080) && m.hover(1080) == 1.0);
        // Not a whole-screen motion.
        assert!(!m.active(1040));
    }
}
