// SPDX-License-Identifier: MIT OR Apache-2.0

//! <string.h> and <strings.h> (C11 7.24, POSIX). memcpy, memmove,
//! memset, memcmp and strlen come from the compiler's runtime
//! (compiler_builtins), which this library links.

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;

use crate::StaticBuf;

/// strlen, for this crate's own use.
///
/// # Safety
///
/// `s` must be a NUL-terminated string.
pub unsafe fn strlen(s: *const c_char) -> usize {
    // SAFETY: Forwarded from the caller.
    unsafe { core::ffi::CStr::from_ptr(s) }.count_bytes()
}

/// The byte at `s + i`.
///
/// # Safety
///
/// `s + i` must be readable.
unsafe fn at(s: *const c_char, i: usize) -> u8 {
    // SAFETY: Forwarded from the caller.
    unsafe { *s.add(i) as u8 }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strnlen(s: *const c_char, max: usize) -> usize {
    let mut n = 0;
    // SAFETY: C guarantees `s` is readable up to its NUL or `max`.
    while n < max && unsafe { at(s, n) } != 0 {
        n += 1;
    }
    n
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memchr(s: *const core::ffi::c_void, c: c_int, n: usize) -> *mut core::ffi::c_void {
    let p = s as *const u8;
    for i in 0..n {
        // SAFETY: C guarantees `n` readable bytes.
        if unsafe { *p.add(i) } == c as u8 {
            return p.wrapping_add(i) as *mut _;
        }
    }
    null_mut()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: Both are NUL-terminated (C's contract).
    unsafe { strncmp(a, b, usize::MAX) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    for i in 0..n {
        // SAFETY: Reading stops at the first NUL or difference.
        let (x, y) = unsafe { (at(a, i), at(b, i)) };
        if x != y || x == 0 {
            return c_int::from(x) - c_int::from(y);
        }
    }
    0
}

fn fold(c: u8) -> c_int {
    c_int::from(c.to_ascii_lowercase())
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: Both are NUL-terminated.
    unsafe { strncasecmp(a, b, usize::MAX) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    for i in 0..n {
        // SAFETY: Reading stops at the first NUL or difference.
        let (x, y) = unsafe { (at(a, i), at(b, i)) };
        if fold(x) != fold(y) || x == 0 {
            return fold(x) - fold(y);
        }
    }
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let mut i = 0;
    // SAFETY: C guarantees `dst` holds `src` and its NUL.
    unsafe {
        loop {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 {
                return dst;
            }
            i += 1;
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: C guarantees `n` writable bytes; the rest is zero-filled.
    unsafe {
        let len = strnlen(src, n);
        core::ptr::copy_nonoverlapping(src, dst, len);
        core::ptr::write_bytes(dst.add(len), 0, n - len);
    }
    dst
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: C guarantees room for both strings.
    unsafe { strcpy(dst.add(strlen(dst)), src) };
    dst
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncat(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: C guarantees room for `n` more bytes and a NUL.
    unsafe {
        let end = dst.add(strlen(dst));
        let len = strnlen(src, n);
        core::ptr::copy_nonoverlapping(src, end, len);
        *end.add(len) = 0;
    }
    dst
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let mut i = 0;
    loop {
        // SAFETY: Stops at the NUL, which also matches `c == 0`.
        let x = unsafe { at(s, i) };
        if x == c as u8 {
            return s.wrapping_add(i) as *mut c_char;
        }
        if x == 0 {
            return null_mut();
        }
        i += 1;
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    let mut found = null_mut();
    let mut i = 0;
    loop {
        // SAFETY: Stops at the NUL.
        let x = unsafe { at(s, i) };
        if x == c as u8 {
            found = s.wrapping_add(i) as *mut c_char;
        }
        if x == 0 {
            return found;
        }
        i += 1;
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    // SAFETY: Both are NUL-terminated.
    let (h, n) = unsafe { (crate::cstr(haystack), crate::cstr(needle)) };
    if n.is_empty() {
        return haystack as *mut c_char;
    }
    h.windows(n.len()).position(|w| w == n).map_or(null_mut(), |i| haystack.wrapping_add(i) as *mut c_char)
}

/// The length of the prefix of `s` whose bytes are (or are not) in `set`.
///
/// # Safety
///
/// Both must be NUL-terminated.
unsafe fn span(s: *const c_char, set: *const c_char, inside: bool) -> usize {
    // SAFETY: Forwarded from the caller.
    let (s, set) = unsafe { (crate::cstr(s), crate::cstr(set)) };
    s.iter().position(|b| set.contains(b) != inside).unwrap_or(s.len())
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    // SAFETY: Both are NUL-terminated.
    unsafe { span(s, accept, true) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    // SAFETY: Both are NUL-terminated.
    unsafe { span(s, reject, false) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    // SAFETY: Both are NUL-terminated.
    unsafe {
        let n = span(s, accept, false);
        if at(s, n) == 0 { null_mut() } else { s.add(n) as *mut c_char }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok_r(s: *mut c_char, delim: *const c_char, save: *mut *mut c_char) -> *mut c_char {
    // SAFETY: `s` (or the saved position) and `delim` are NUL-terminated.
    unsafe {
        let mut p = if s.is_null() { *save } else { s };
        if p.is_null() {
            return null_mut();
        }
        p = p.add(span(p, delim, true));
        if *p == 0 {
            *save = null_mut();
            return null_mut();
        }
        let end = p.add(span(p, delim, false));
        if *end == 0 {
            *save = null_mut();
        } else {
            *end = 0;
            *save = end.add(1);
        }
        p
    }
}

/// strtok's saved position.
static TOK: core::sync::atomic::AtomicPtr<c_char> = core::sync::atomic::AtomicPtr::new(null_mut());

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    // SAFETY: As for strtok_r; the position lives in TOK.
    unsafe { strtok_r(s, delim, TOK.as_ptr()) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: `s` is readable up to its NUL or `n`; the copy is new.
    unsafe {
        let len = strnlen(s, n);
        let p = crate::stdlib::malloc(len + 1) as *mut c_char;
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(s, p, len);
            *p.add(len) = 0;
        }
        p
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: `s` is NUL-terminated.
    unsafe { strndup(s, usize::MAX) }
}

static ERROR_TEXT: StaticBuf<64> = StaticBuf::new();

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    ERROR_TEXT.set(slate_rt::Errno(errnum).message().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_and_search() {
        // SAFETY: C-string literals.
        unsafe {
            assert!(strcmp(c"abc".as_ptr(), c"abd".as_ptr()) < 0);
            assert_eq!(strncmp(c"abcx".as_ptr(), c"abcy".as_ptr(), 3), 0);
            assert_eq!(strcasecmp(c"HeLLo".as_ptr(), c"hello".as_ptr()), 0);
            let s = c"a/b/c".as_ptr();
            assert_eq!(strrchr(s, b'/' as c_int).offset_from(s), 3);
            assert_eq!(strstr(s, c"b/".as_ptr()).offset_from(s), 2);
            assert!(strchr(s, b'z' as c_int).is_null());
            assert_eq!(strspn(c"  x".as_ptr(), c" ".as_ptr()), 2);
            assert_eq!(strcspn(c"ab,cd".as_ptr(), c",".as_ptr()), 2);
        }
    }

    #[test]
    fn tokens() {
        let mut buf = *b",one,,two\0";
        let mut save = null_mut();
        let p = buf.as_mut_ptr() as *mut c_char;
        // SAFETY: A NUL-terminated buffer.
        unsafe {
            assert_eq!(crate::cstr(strtok_r(p, c",".as_ptr(), &mut save)), b"one");
            assert_eq!(crate::cstr(strtok_r(null_mut(), c",".as_ptr(), &mut save)), b"two");
            assert!(strtok_r(null_mut(), c",".as_ptr(), &mut save).is_null());
        }
    }
}
