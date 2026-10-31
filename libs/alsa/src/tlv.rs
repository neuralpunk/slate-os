// SPDX-License-Identifier: MIT OR Apache-2.0

//! Volume scales a mixer reads with `TLV_READ` (`sound/tlv.h`), so it can
//! show decibels.

use crate::abi::{TLV_DB_SCALE_MUTE, TLVT_DB_SCALE};

/// A dB scale: step 0 is `min_cdb` hundredths of a dB, each step
/// `step_cdb` more; `mute` if the lowest step is silence.
pub fn db_scale(min_cdb: i32, step_cdb: u32, mute: bool) -> [u32; 4] {
    [TLVT_DB_SCALE, 8, min_cdb as u32, (step_cdb & 0xffff) | if mute { TLV_DB_SCALE_MUTE } else { 0 }]
}

/// As bytes, for the caller's buffer.
pub fn to_bytes(words: &[u32; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_db_scale() {
        // -95.25 dB in 0.75 dB steps, muting at the bottom.
        let s = db_scale(-9525, 75, true);
        assert_eq!(s, [1, 8, (-9525i32) as u32, 75 | 0x10000]);
        assert_eq!(&to_bytes(&s)[..4], &[1, 0, 0, 0]);
    }
}
