// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checksums used by ext4 metadata: CRC-32C (Castagnoli, reflected
//! polynomial 0x82F63B78) without the final inversion, chained through a
//! seed as the format documentation describes, and the CRC-16 (reflected
//! polynomial 0xA001) of the older `gdt_csum` feature.

const fn table32() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

const fn table16() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xA001 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static T32: [u32; 256] = table32();
static T16: [u16; 256] = table16();

/// CRC-32C of `data` continuing from `crc` (no pre- or post-inversion).
pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = T32[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// CRC-16 of `data` continuing from `crc`.
pub fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = T16[((crc ^ u16::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_value() {
        // The standard CRC-32C check value: inverted in and out.
        assert_eq!(!crc32c(!0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc16_check_value() {
        // CRC-16/ARC check value (initial value 0).
        assert_eq!(crc16(0, b"123456789"), 0xBB3D);
    }
}
