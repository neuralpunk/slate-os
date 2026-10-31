// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stream's two positions in frames (ADR 0184): the hardware's
//! (`hw_ptr`, what the card has played or recorded) and the program's
//! (`appl_ptr`, what it has written or read). Both count up from 0 and
//! wrap at the *boundary*, a large multiple of the buffer size, so the
//! offset in the buffer is the position modulo the buffer size.

/// The wrap point for a buffer of `buffer_size` frames: the buffer size
/// doubled while twice it plus a buffer still fits a signed 64-bit count
/// (alsa-lib's `snd_pcm_sframes_t`).
pub fn boundary(buffer_size: u64) -> u64 {
    let mut b = buffer_size.max(1);
    while b <= (i64::MAX as u64 - buffer_size) / 2 {
        b *= 2;
    }
    b
}

/// `a - b` along positions that wrap at `boundary`.
pub fn distance(a: u64, b: u64, boundary: u64) -> u64 {
    if a >= b { a - b } else { a + boundary - b }
}

/// `a + n`, wrapped at `boundary`.
pub fn advance(a: u64, n: u64, boundary: u64) -> u64 {
    let s = a + n;
    if s >= boundary { s - boundary } else { s }
}

/// `a - b` along positions that wrap at `boundary`, as a signed count:
/// the shorter way round (the boundary is far larger than any buffer, so
/// two positions of one stream are never half of it apart).
pub fn signed_distance(a: u64, b: u64, boundary: u64) -> i64 {
    let d = distance(a, b, boundary);
    if d > boundary / 2 { -(distance(b, a, boundary) as i64) } else { d as i64 }
}

/// Frames a playback program may write: the buffer less what is waiting
/// to be played. More than the buffer once the card has played past the
/// program's frames (an underrun).
pub fn playback_avail(hw: u64, appl: u64, buffer_size: u64, boundary: u64) -> i64 {
    buffer_size as i64 - signed_distance(appl, hw, boundary)
}

/// Frames a capture program may read: what the card recorded that the
/// program hasn't read (more than the buffer after an overrun).
pub fn capture_avail(hw: u64, appl: u64, boundary: u64) -> i64 {
    signed_distance(hw, appl, boundary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boundary_is_a_large_multiple() {
        let b = boundary(4096);
        assert_eq!(b % 4096, 0);
        assert!(b > 1 << 60);
        assert!(b as u128 * 2 > i64::MAX as u128 - 4096);
    }

    #[test]
    fn pointers_wrap() {
        let b = 1 << 20;
        assert_eq!(distance(5, b - 3, b), 8);
        assert_eq!(advance(b - 3, 8, b), 5);
        assert_eq!(playback_avail(100, 100, 4096, b), 4096);
        assert_eq!(playback_avail(100, 4196, 4096, b), 0);
        // The card's position just before the wrap, the program's after it.
        assert_eq!(playback_avail(b - 3, 5, 4096, b), 4096 - 8);
        assert_eq!(capture_avail(4096, 1000, b), 3096);
        // The card past the program's frames: an underrun's worth more.
        assert_eq!(playback_avail(5000, 4000, 4096, b), 4096 + 1000);
        assert_eq!(playback_avail(2, b - 10, 4096, b), 4096 + 12);
        assert_eq!(signed_distance(3, 5, b), -2);
    }
}
