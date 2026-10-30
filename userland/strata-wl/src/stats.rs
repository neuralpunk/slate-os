// SPDX-License-Identifier: MIT OR Apache-2.0

//! Frame timings (M31 phase 1): with `strata.stats` on the kernel's
//! command line the bridge times each frame it shows — how long the
//! compositor took to hand it over after it was asked for, the copy into
//! the window's canvas, and presenting it to Strata — and counts the
//! bytes it copied. Once frames stop for [`STILL_US`] it prints one
//! `strata-wl-stats:` line about them, in microseconds, as Strata's own
//! `strata-stats:` lines do; `cargo xtask flatpak --measure` reads both.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::conn::percentile;

/// How long frames must stop before a summary.
pub const STILL_US: i64 = 400_000;

#[derive(Clone, Copy, Debug)]
struct Frame {
    /// When it was shown.
    at: i64,
    wait: i64,
    convert: i64,
    present: i64,
    /// Bytes copied: the compositor's into ours, ours into the canvas,
    /// and the canvas into Strata's buffer (compared, then copied).
    bytes: u64,
}

#[derive(Debug, Default)]
pub struct FrameStats {
    frames: Vec<Frame>,
}

impl FrameStats {
    /// A frame shown at `at`: waited for `wait`, copied in `convert`,
    /// presented in `present` (µs), `bytes` copied on the way.
    pub fn frame(&mut self, at: i64, wait: i64, convert: i64, present: i64, bytes: u64) {
        self.frames.push(Frame { at, wait, convert, present, bytes });
    }

    /// Whether a summary is waiting for frames to stop.
    pub fn pending(&self) -> bool {
        !self.frames.is_empty()
    }

    /// The summary, if frames stopped by `now` (µs); then starts again.
    pub fn still(&mut self, now: i64) -> Option<String> {
        let last = self.frames.last()?.at;
        if now - last < STILL_US {
            return None;
        }
        let f = core::mem::take(&mut self.frames);
        let n = f.len();
        let col = |g: fn(&Frame) -> i64| -> Vec<i64> { f.iter().map(g).collect() };
        let (mut wait, mut convert, mut present) = (col(|x| x.wait), col(|x| x.convert), col(|x| x.present));
        let mut gaps: Vec<i64> = f.windows(2).map(|w| w[1].at - w[0].at).collect();
        let bytes = f.iter().map(|x| x.bytes).sum::<u64>() / n as u64;
        Some(format!(
            "strata-wl-stats: frames={n} interval_p50={} wait_p50={} convert_p50={} convert_p95={} present_p50={} present_p95={} bytes_per_frame={bytes}",
            percentile(&mut gaps, 50),
            percentile(&mut wait, 50),
            percentile(&mut convert, 50),
            percentile(&mut convert, 95),
            percentile(&mut present, 50),
            percentile(&mut present, 95),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_once_frames_stop() {
        let mut s = FrameStats::default();
        assert!(s.still(0).is_none());
        for i in 0..4 {
            s.frame(1000 + i * 16_000, 100, 200 + i, 300, 4000);
        }
        assert!(s.pending());
        assert!(s.still(50_000 + 16_000 * 3).is_none(), "not still yet");
        let line = s.still(1000 + 48_000 + STILL_US).unwrap();
        assert_eq!(
            line,
            "strata-wl-stats: frames=4 interval_p50=16000 wait_p50=100 convert_p50=202 convert_p95=203 present_p50=300 present_p95=300 bytes_per_frame=4000"
        );
        assert!(!s.pending());
    }
}
