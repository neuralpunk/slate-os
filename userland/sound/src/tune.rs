// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-test tune: a soft music-box phrase of about four and a half
//! seconds. A G major arpeggio rises, falls back and settles on a G major
//! chord; each note is a sine with a little of its second and third
//! harmonics (a bell's warmth), a gentle attack and a long decay, panned a
//! little left or right in turn. The whole is quiet: its peak is a quarter
//! of full scale, and it fades out at the end.

use alloc::vec::Vec;

use slate_math::{cos_, exp_, sin_};

/// G3, G4, B4, D5, E5, G5 (equal temperament, A4 = 440 Hz).
pub const G3: f64 = 196.00;
pub const G4: f64 = 392.00;
pub const B4: f64 = 493.88;
pub const D5: f64 = 587.33;
pub const E5: f64 = 659.26;
pub const G5: f64 = 783.99;

/// (start in seconds, frequency, loudness, place left to right 0..1,
/// decay time constant in seconds).
const NOTES: [(f64, f64, f64, f64, f64); 12] = [
    (0.00, G4, 1.00, 0.40, 0.70),
    (0.30, B4, 0.90, 0.60, 0.70),
    (0.60, D5, 0.85, 0.40, 0.70),
    (0.90, G5, 0.75, 0.60, 0.80),
    (1.35, E5, 0.75, 0.45, 0.70),
    (1.65, D5, 0.80, 0.55, 0.70),
    (1.95, B4, 0.85, 0.45, 0.80),
    // The chord, its notes a few milliseconds apart, as a hand plays it.
    (2.40, G3, 0.55, 0.50, 1.20),
    (2.41, G4, 0.80, 0.42, 1.20),
    (2.43, B4, 0.60, 0.58, 1.10),
    (2.45, D5, 0.55, 0.50, 1.10),
    (2.47, G5, 0.30, 0.55, 1.00),
];

/// The tune's length in seconds.
pub const SECONDS: f64 = 4.6;
/// Its peak, as a share of full scale.
pub const PEAK: f64 = 0.25;
/// The fade at the end, in seconds.
const FADE: f64 = 0.5;
/// Each note's attack, in seconds.
const ATTACK: f64 = 0.02;

/// The tune at `rate` frames a second, 16-bit, `channels` interleaved
/// (one: mixed to mono; two: left and right).
pub fn render(rate: u32, channels: u32) -> Vec<i16> {
    let n = (SECONDS * f64::from(rate)) as usize;
    let mut left = alloc::vec![0.0f64; n];
    let mut right = alloc::vec![0.0f64; n];
    let r = f64::from(rate);
    for &(start, freq, gain, pan, tau) in &NOTES {
        let first = (start * r) as usize;
        // Each partial turns a phasor (cos, sin) by its step per frame;
        // the envelope decays by one factor per frame.
        let partials = [(1.0, 1.0), (2.0, 0.18), (3.0, 0.05)];
        let mut ph: Vec<(f64, f64, f64, f64, f64)> = partials
            .iter()
            .map(|&(k, a)| {
                let w = 2.0 * core::f64::consts::PI * freq * k / r;
                (1.0, 0.0, cos_(w), sin_(w), a)
            })
            .collect();
        let decay = exp_(-1.0 / (tau * r));
        let attack = ATTACK * r;
        let mut env = 1.0;
        let (gl, gr) = (gain * (1.0 - pan), gain * pan);
        for (i, at) in (first..n).enumerate() {
            let rise = if (i as f64) < attack { i as f64 / attack } else { 1.0 };
            let mut v = 0.0;
            for p in ph.iter_mut() {
                v += p.1 * p.4;
                // Rotate: (c, s) <- (c cos w - s sin w, s cos w + c sin w).
                let (c, s) = (p.0 * p.2 - p.1 * p.3, p.1 * p.2 + p.0 * p.3);
                (p.0, p.1) = (c, s);
            }
            let x = v * env * rise;
            left[at] += x * gl;
            right[at] += x * gr;
            env *= decay;
            if env < 1e-4 {
                break;
            }
        }
    }
    // Quiet, with a fade at the end.
    let peak = left.iter().chain(right.iter()).fold(0.0f64, |m, v| m.max(v.abs())).max(1e-9);
    let scale = PEAK / peak * 32767.0;
    let fade = (FADE * r) as usize;
    let mut out = Vec::with_capacity(n * channels as usize);
    for i in 0..n {
        let f = if i + fade > n { (n - i) as f64 / fade as f64 } else { 1.0 };
        let (l, rr) = (left[i] * scale * f, right[i] * scale * f);
        if channels == 1 {
            out.push(((l + rr) / 2.0) as i16);
        } else {
            out.push(l as i16);
            out.push(rr as i16);
            out.extend(core::iter::repeat_n(0, channels.saturating_sub(2) as usize));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The power of `freq` in `x`, as the sound scenario measures it.
    fn goertzel(x: &[f64], freq: f64, rate: f64) -> f64 {
        let w = 2.0 * core::f64::consts::PI * freq / rate;
        let coeff = 2.0 * w.cos();
        let (mut s1, mut s2) = (0.0, 0.0);
        for &v in x {
            let s = v + coeff * s1 - s2;
            s2 = s1;
            s1 = s;
        }
        s1 * s1 + s2 * s2 - coeff * s1 * s2
    }

    #[test]
    fn the_tune_is_short_quiet_and_in_tune() {
        let t = render(48000, 2);
        assert_eq!(t.len(), 2 * (4.6 * 48000.0) as usize);
        let peak = t.iter().map(|v| i32::from(*v).abs()).max().unwrap();
        assert!(peak <= 8192 && peak > 7000, "peak {peak}");
        // It starts at silence and fades to it: no clicks.
        assert!(t[0].abs() < 50 && t[1].abs() < 50);
        assert!(t[t.len() - 2].abs() < 50);
        // The notes are there, and a note not in the tune is not.
        let mono: std::vec::Vec<f64> = t.chunks(2).map(|f| f64::from(f[0]) + f64::from(f[1])).collect();
        let off = goertzel(&mono, 440.0, 48000.0);
        for f in [G4, B4, D5, G5] {
            assert!(goertzel(&mono, f, 48000.0) > 20.0 * off, "{f} Hz");
        }
        // Mono and other rates are the same tune.
        let m = render(44100, 1);
        assert_eq!(m.len(), (4.6 * 44100.0) as usize);
    }
}
