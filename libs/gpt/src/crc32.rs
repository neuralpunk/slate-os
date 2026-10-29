// SPDX-License-Identifier: MIT OR Apache-2.0

//! CRC-32 as used by GPT (UEFI 2.10 section 5.3.2 refers to the standard
//! CRC-32: polynomial 0x04C11DB7, reflected, init and xorout 0xFFFFFFFF).

const POLY_REFLECTED: u32 = 0xEDB8_8320;

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { POLY_REFLECTED ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Compute the CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn check_value() {
        // The standard "check" value for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
