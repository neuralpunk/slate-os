// SPDX-License-Identifier: MIT OR Apache-2.0

//! <ctype.h> (C11 7.4) in the "C" locale: ASCII classes; other values
//! (including EOF) are in no class.

use core::ffi::c_int;

fn byte(c: c_int) -> Option<u8> {
    u8::try_from(c).ok().filter(u8::is_ascii)
}

macro_rules! class {
    ($($name:ident => $test:expr;)*) => {$(
        #[cfg_attr(target_os = "none", unsafe(no_mangle))]
        pub extern "C" fn $name(c: c_int) -> c_int {
            c_int::from(byte(c).is_some_and($test))
        }
    )*};
}

class! {
    isalnum => |b: u8| b.is_ascii_alphanumeric();
    isalpha => |b: u8| b.is_ascii_alphabetic();
    isblank => |b: u8| b == b' ' || b == b'\t';
    iscntrl => |b: u8| b.is_ascii_control();
    isdigit => |b: u8| b.is_ascii_digit();
    isgraph => |b: u8| b.is_ascii_graphic();
    islower => |b: u8| b.is_ascii_lowercase();
    isprint => |b: u8| b.is_ascii_graphic() || b == b' ';
    ispunct => |b: u8| b.is_ascii_punctuation();
    // C's white space includes vertical tab, which Rust's does not.
    isspace => |b: u8| b.is_ascii_whitespace() || b == 0x0B;
    isupper => |b: u8| b.is_ascii_uppercase();
    isxdigit => |b: u8| b.is_ascii_hexdigit();
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tolower(c: c_int) -> c_int {
    byte(c).map_or(c, |b| c_int::from(b.to_ascii_lowercase()))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn toupper(c: c_int) -> c_int {
    byte(c).map_or(c, |b| c_int::from(b.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(isspace(0x0B), 1);
        assert_eq!(isdigit(b'7'.into()), 1);
        assert_eq!(isalpha(-1), 0);
        assert_eq!(isprint(b' '.into()), 1);
        assert_eq!(toupper(b'q'.into()), b'Q'.into());
        assert_eq!(tolower(200), 200);
    }
}
