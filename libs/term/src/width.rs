// SPDX-License-Identifier: MIT OR Apache-2.0

//! How many terminal columns a character takes (ADR 0099): two for East
//! Asian wide and fullwidth characters (UAX #11), none for combining
//! marks and format characters, one for the rest. The tables are made
//! from the Unicode Character Database by `cargo xtask unicode`.

use crate::width_table::{WIDE, ZERO};

pub use crate::width_table::UNICODE_VERSION;

fn within(table: &[(u32, u32)], c: u32) -> bool {
    table
        .binary_search_by(|&(a, b)| {
            if b < c {
                core::cmp::Ordering::Less
            } else if a > c {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The columns `c` takes: 0, 1 or 2. Control characters count as one
/// (the emulator acts on them rather than printing them).
pub fn width(c: char) -> usize {
    let c = c as u32;
    if c < 0x300 {
        return 1;
    }
    if within(ZERO, c) {
        0
    } else if within(WIDE, c) {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths() {
        assert_eq!(width('a'), 1);
        assert_eq!(width('é'), 1);
        assert_eq!(width('\u{AD}'), 1);
        // Combining acute accent, zero width joiner, variation selector 16.
        assert_eq!(width('\u{301}'), 0);
        assert_eq!(width('\u{200D}'), 0);
        assert_eq!(width('\u{FE0F}'), 0);
        // CJK, Hangul, fullwidth forms, an emoji.
        assert_eq!(width('中'), 2);
        assert_eq!(width('한'), 2);
        assert_eq!(width('Ａ'), 2);
        assert_eq!(width('😀'), 2);
        // A Hangul jamo vowel joins the syllable before it.
        assert_eq!(width('\u{1161}'), 0);
        // Box drawing and Greek stay narrow; an unassigned plane-2 point is wide.
        assert_eq!(width('─'), 1);
        assert_eq!(width('λ'), 1);
        assert_eq!(width('\u{2FFF0}'), 2);
    }

    #[test]
    fn tables_are_sorted() {
        for t in [ZERO, WIDE] {
            assert!(t.windows(2).all(|w| w[0].1 < w[1].0));
            assert!(t.iter().all(|&(a, b)| a <= b));
        }
    }
}
