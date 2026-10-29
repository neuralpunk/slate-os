// SPDX-License-Identifier: MIT OR Apache-2.0

//! The firmware's text console (EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL, UEFI 2.10
//! §12.4), which OVMF copies to the serial port.

use core::sync::atomic::Ordering;

/// Write `s` (UCS-2, in pieces), while boot services last.
pub fn print(s: &str) {
    if crate::EXITED.load(Ordering::Relaxed) {
        return;
    }
    let out = crate::st().con_out;
    let mut buf = [0u16; 129];
    let mut n = 0;
    let flush = |buf: &mut [u16; 129], n: &mut usize| {
        buf[*n] = 0;
        // SAFETY: The firmware's console output protocol, a NUL-terminated
        // string.
        unsafe { ((*out).output_string)(out, buf.as_ptr()) };
        *n = 0;
    };
    for c in s.encode_utf16() {
        if n == 128 {
            flush(&mut buf, &mut n);
        }
        buf[n] = c;
        n += 1;
    }
    flush(&mut buf, &mut n);
}

/// Clear the console.
pub fn clear() {
    let out = crate::st().con_out;
    // SAFETY: The firmware's console output protocol.
    unsafe {
        ((*out).clear_screen)(out);
        ((*out).enable_cursor)(out, false);
    }
}

/// A key, if one was pressed: (scan code, character).
pub fn key() -> Option<(u16, u16)> {
    let input = crate::st().con_in;
    let mut k = crate::efi::InputKey { scan_code: 0, unicode_char: 0 };
    // SAFETY: The firmware's console input protocol.
    let s = unsafe { ((*input).read_key_stroke)(input, &mut k) };
    (s == crate::efi::SUCCESS).then_some((k.scan_code, k.unicode_char))
}

/// The console's size in characters (QueryMode on the current mode,
/// §12.4.5).
pub fn size() -> (usize, usize) {
    let out = crate::st().con_out;
    let (mut cols, mut rows) = (80, 25);
    // SAFETY: The firmware's console output protocol and its mode.
    unsafe {
        let mode = (*(*out).mode).mode;
        if mode < 0 || crate::efi::is_error(((*out).query_mode)(out, mode as usize, &mut cols, &mut rows)) {
            return (80, 25);
        }
    }
    (cols, rows)
}

/// Write `s` at a column and row, in an attribute.
pub fn at(col: usize, row: usize, attr: usize, s: &str) {
    let out = crate::st().con_out;
    // SAFETY: The firmware's console output protocol.
    unsafe {
        ((*out).set_attribute)(out, attr);
        ((*out).set_cursor_position)(out, col, row);
    }
    print(s);
}

/// Back to the console's plain colours.
pub fn reset() {
    let out = crate::st().con_out;
    // SAFETY: The firmware's console output protocol.
    unsafe { ((*out).set_attribute)(out, crate::efi::LIGHTGRAY) };
}
