// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frame timings for `cargo xtask bench` (ADR 0062). With `strata.stats`
//! on the kernel command line Strata times each frame it draws (drawing,
//! then presenting), how long input took to reach the screen (from the
//! event's timestamp to the end of the frame that showed it), and how long
//! a key sent to an app took to come back as the app's new contents on
//! the screen. Once the screen has been still for [`STILL_NS`] it prints
//! one `strata-stats:` line about the frames since the last one, in
//! microseconds, and starts again; the bench reads those lines.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::wm::WinId;

/// How long the screen must be still before a summary.
pub const STILL_NS: i64 = 400_000_000;
/// A key whose app has shown nothing new after this long is forgotten
/// (a key that changes nothing).
const KEY_TIMEOUT_NS: i64 = 1_000_000_000;

#[derive(Clone, Copy, Debug)]
struct Frame {
    start: i64,
    draw: i64,
    present: i64,
    full: bool,
    rows: u32,
}

/// A key sent to an app, waiting to be seen.
#[derive(Clone, Copy, Debug)]
struct Key {
    window: WinId,
    stamp: i64,
    /// The app has sent new contents since.
    answered: bool,
}

/// The timings, while on.
#[derive(Debug, Default)]
pub struct Stats {
    pub on: bool,
    frames: Vec<Frame>,
    last_end: i64,
    /// The oldest input not yet on the screen.
    input: Option<i64>,
    inputs: Vec<i64>,
    /// From each batch of input's newest event to Strata having read it.
    wakes: Vec<i64>,
    /// The loop's work before drawing, and after reading input.
    preps: Vec<i64>,
    handles: Vec<i64>,
    keys_waiting: Vec<Key>,
    keys: Vec<i64>,
}

impl Stats {
    pub fn new(on: bool) -> Stats {
        Stats { on, ..Stats::default() }
    }

    /// There are frames not yet summed up.
    pub fn pending(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Input that happened at `stamp` (0: none) is being handled.
    pub fn input(&mut self, stamp: i64) {
        if self.on && stamp > 0 && self.input.is_none() {
            self.input = Some(stamp);
        }
    }

    /// Input whose newest event happened at `stamp` was read at `now`.
    pub fn read(&mut self, stamp: i64, now: i64) {
        if self.on && stamp > 0 {
            self.wakes.push(now - stamp);
        }
    }

    /// The loop's work: `prep` before drawing, `handle` after reading.
    pub fn work(&mut self, prep: i64, handle: i64) {
        if self.on && !self.frames.is_empty() {
            self.preps.push(prep);
            self.handles.push(handle);
        }
    }

    /// Nothing needed drawing: the input changed nothing on the screen.
    pub fn nothing_drawn(&mut self) {
        self.input = None;
    }

    /// A key that happened at `stamp` went to the app in `window`.
    pub fn key_sent(&mut self, window: WinId, stamp: i64) {
        if self.on && stamp > 0 {
            self.keys_waiting.push(Key { window, stamp, answered: false });
        }
    }

    /// The app in `window` sent new contents.
    pub fn contents(&mut self, window: WinId) {
        for k in self.keys_waiting.iter_mut().filter(|k| k.window == window) {
            k.answered = true;
        }
    }

    /// A frame: started drawing at `start`, presented from `drawn` to
    /// `end`, `rows` rows sent to the display.
    pub fn frame(&mut self, start: i64, drawn: i64, end: i64, full: bool, rows: u32) {
        if !self.on {
            return;
        }
        self.frames.push(Frame { start, draw: drawn - start, present: end - drawn, full, rows });
        self.last_end = end;
        if let Some(i) = self.input.take() {
            self.inputs.push(end - i);
        }
        let keys = &mut self.keys;
        self.keys_waiting.retain(|k| {
            if k.answered {
                keys.push(end - k.stamp);
                false
            } else {
                end - k.stamp < KEY_TIMEOUT_NS
            }
        });
    }

    /// The summary of the frames since the last one, once the screen has
    /// been still long enough at `now`.
    pub fn still(&mut self, now: i64) -> Option<String> {
        self.keys_waiting.retain(|k| now - k.stamp < KEY_TIMEOUT_NS);
        if !self.on || self.frames.is_empty() || now - self.last_end < STILL_NS || !self.keys_waiting.is_empty() {
            return None;
        }
        let frames = core::mem::take(&mut self.frames);
        let mut s = String::from("strata-stats:");
        let span = frames.last().map_or(0, |f| f.start + f.draw + f.present) - frames[0].start;
        let full = frames.iter().filter(|f| f.full).count();
        let rows: u64 = frames.iter().map(|f| u64::from(f.rows)).sum();
        let _ = write!(s, " frames={} full={full} rows={rows} span_us={}", frames.len(), span / 1000);
        let series = [
            ("frame", frames.iter().map(|f| f.draw + f.present).collect::<Vec<_>>()),
            ("draw", frames.iter().map(|f| f.draw).collect()),
            ("present", frames.iter().map(|f| f.present).collect()),
            ("input", core::mem::take(&mut self.inputs)),
            ("wake", core::mem::take(&mut self.wakes)),
            ("prep", core::mem::take(&mut self.preps)),
            ("handle", core::mem::take(&mut self.handles)),
            ("key", core::mem::take(&mut self.keys)),
        ];
        for (name, mut v) in series {
            summary(&mut s, name, &mut v);
        }
        // Each frame's drawing, in order: which frame of a burst was slow.
        let _ = write!(s, " draws_us=");
        for (i, f) in frames.iter().enumerate() {
            let _ = write!(s, "{}{}", if i > 0 { "," } else { "" }, f.draw / 1000);
        }
        Some(s)
    }
}

/// `NAME_n`, `_avg_us`, `_p95_us` and `_max_us` of the times in `v`.
fn summary(s: &mut String, name: &str, v: &mut [i64]) {
    let _ = write!(s, " {name}_n={}", v.len());
    if v.is_empty() {
        return;
    }
    v.sort_unstable();
    let avg = v.iter().sum::<i64>() / v.len() as i64;
    let p95 = v[(v.len() * 95).div_ceil(100) - 1];
    let max = v[v.len() - 1];
    let _ = write!(s, " {name}_avg_us={} {name}_p95_us={} {name}_max_us={}", avg / 1000, p95 / 1000, max / 1000);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i64 = 1_000_000;

    #[test]
    fn frames_and_input() {
        let mut s = Stats::new(true);
        s.input(5 * MS);
        s.frame(10 * MS, 14 * MS, 16 * MS, true, 800);
        s.input(20 * MS);
        s.frame(20 * MS, 22 * MS, 23 * MS, false, 40);
        assert_eq!(s.still(23 * MS + STILL_NS - 1), None);
        let line = s.still(23 * MS + STILL_NS).unwrap();
        assert_eq!(
            line,
            "strata-stats: frames=2 full=1 rows=840 span_us=13000 frame_n=2 frame_avg_us=4500 frame_p95_us=6000 \
             frame_max_us=6000 draw_n=2 draw_avg_us=3000 draw_p95_us=4000 draw_max_us=4000 present_n=2 \
             present_avg_us=1500 present_p95_us=2000 present_max_us=2000 input_n=2 input_avg_us=7000 \
             input_p95_us=11000 input_max_us=11000 wake_n=0 prep_n=0 handle_n=0 key_n=0 draws_us=4000,2000"
        );
        // Reset: nothing more until new frames.
        assert_eq!(s.still(10_000 * MS), None);
    }

    #[test]
    fn keys_wait_for_their_app() {
        let mut s = Stats::new(true);
        s.key_sent(3, 100 * MS);
        // A frame before the app answered: no key yet, and no summary
        // while the key waits.
        s.frame(101 * MS, 102 * MS, 103 * MS, false, 10);
        assert_eq!(s.still(103 * MS + STILL_NS), None);
        s.contents(4);
        s.frame(104 * MS, 105 * MS, 106 * MS, false, 10);
        s.contents(3);
        s.frame(107 * MS, 108 * MS, 109 * MS, false, 10);
        let line = s.still(109 * MS + STILL_NS).unwrap();
        assert!(
            line.ends_with(
                "wake_n=0 prep_n=0 handle_n=0 key_n=1 key_avg_us=9000 key_p95_us=9000 key_max_us=9000 \
                 draws_us=1000,1000,1000"
            ),
            "{line}"
        );
    }

    #[test]
    fn unanswered_keys_are_forgotten_and_off_records_nothing() {
        let mut s = Stats::new(true);
        s.key_sent(1, MS);
        s.frame(2 * MS, 3 * MS, 4 * MS, false, 1);
        s.frame(KEY_TIMEOUT_NS + 2 * MS, KEY_TIMEOUT_NS + 3 * MS, KEY_TIMEOUT_NS + 4 * MS, false, 1);
        assert!(s.still(KEY_TIMEOUT_NS + 4 * MS + STILL_NS).unwrap().ends_with("key_n=0 draws_us=1000,1000"));
        let mut off = Stats::new(false);
        off.input(MS);
        off.frame(MS, 2 * MS, 3 * MS, true, 1);
        assert_eq!(off.still(STILL_NS * 10), None);
    }
}
