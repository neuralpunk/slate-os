// SPDX-License-Identifier: MIT OR Apache-2.0

//! <stdlib.h> (C11 7.22, POSIX setenv): memory, exit, the environment,
//! number conversion, sorting, pseudo-random numbers; and <assert.h>'s
//! failure report.

use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use slate_rt::Errno;
use slate_rt::sync::Mutex;

use crate::{cstr, set_errno};

// --- memory ---------------------------------------------------------------

/// On Slate, the blocks are the hardened allocator's (ADR 0094), which
/// knows each block's size: `free` needs no header, and catches a pointer
/// it did not hand out or one freed twice. On the host (unit tests), each
/// block starts with a 16-byte header holding its size.
#[cfg(target_os = "none")]
mod blocks {
    use alloc::alloc::{GlobalAlloc, Layout};

    use crate::start::ALLOCATOR;

    pub fn alloc(size: usize) -> *mut u8 {
        let Ok(l) = Layout::from_size_align(size.max(1), 16) else { return core::ptr::null_mut() };
        // SAFETY: A non-zero layout.
        unsafe { ALLOCATOR.alloc(l) }
    }

    /// # Safety
    ///
    /// `p` must not be used after (a bad `p` stops the program).
    pub unsafe fn free(p: *mut u8) {
        // SAFETY: The caller gives the block up.
        unsafe { ALLOCATOR.free_unsized(p) }
    }

    /// The bytes usable at `p`, a live block.
    pub fn size(p: *mut u8) -> usize {
        ALLOCATOR.usable_size(p).unwrap_or(0)
    }
}

#[cfg(not(target_os = "none"))]
mod blocks {
    use alloc::alloc::Layout;

    const HEADER: usize = 16;

    fn layout(size: usize) -> Option<Layout> {
        Layout::from_size_align(size.checked_add(HEADER)?, 16).ok()
    }

    pub fn alloc(size: usize) -> *mut u8 {
        let Some(l) = layout(size) else { return core::ptr::null_mut() };
        // SAFETY: The layout is non-zero; the header is written before use.
        unsafe {
            let p = alloc::alloc::alloc(l);
            if p.is_null() {
                return p;
            }
            (p as *mut usize).write(size);
            p.add(HEADER)
        }
    }

    /// # Safety
    ///
    /// `p` must be a live block from `alloc`.
    pub unsafe fn free(p: *mut u8) {
        // SAFETY: The header precedes every block.
        unsafe {
            let size = size(p);
            alloc::alloc::dealloc(p.sub(HEADER), layout(size).unwrap());
        }
    }

    pub fn size(p: *mut u8) -> usize {
        // SAFETY: The header precedes every block.
        unsafe { (p.sub(HEADER) as *const usize).read() }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn malloc(size: usize) -> *mut c_void {
    let p = blocks::alloc(size);
    if p.is_null() {
        set_errno(Errno::ENOMEM);
    }
    p as *mut c_void
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` came from malloc (a bad one is caught on Slate).
    unsafe { blocks::free(p as *mut u8) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn calloc(n: usize, size: usize) -> *mut c_void {
    let Some(total) = n.checked_mul(size) else {
        set_errno(Errno::ENOMEM);
        return null_mut();
    };
    let p = malloc(total);
    if !p.is_null() {
        // SAFETY: A fresh block of `total` bytes.
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, total) };
    }
    p
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn realloc(p: *mut c_void, size: usize) -> *mut c_void {
    if p.is_null() {
        return malloc(size);
    }
    let q = malloc(size);
    if !q.is_null() {
        // SAFETY: Both blocks hold at least the smaller size.
        unsafe {
            core::ptr::copy_nonoverlapping(p as *const u8, q as *mut u8, blocks::size(p as *mut u8).min(size));
            free(p);
        }
    }
    q
}

// --- exit -------------------------------------------------------------------

/// atexit(3) functions, in registration order.
static AT_EXIT: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn atexit(f: extern "C" fn()) -> c_int {
    AT_EXIT.lock().push(f);
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn exit(status: c_int) -> ! {
    // Last registered runs first; a function may register more.
    loop {
        let f = AT_EXIT.lock().pop();
        match f {
            Some(f) => f(),
            None => break,
        }
    }
    crate::stdio::flush_all();
    slate_rt::process::exit_now(status)
}

#[allow(non_snake_case)] // C's name.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn _Exit(status: c_int) -> ! {
    slate_rt::process::exit_now(status)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn abort() -> ! {
    crate::stdio::flush_all();
    let _ = slate_rt::signal::set(slate_rt::signal::SIGABRT, slate_rt::signal::Disposition::Default);
    let _ = slate_rt::process::kill(slate_rt::process::getpid(), slate_rt::signal::SIGABRT);
    slate_rt::process::exit_now(128 + slate_rt::signal::SIGABRT)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_fail(
    expr: *const c_char,
    file: *const c_char,
    line: c_int,
    func: *const c_char,
) -> ! {
    // SAFETY: The assert macro passes string literals.
    let (e, f, func) = unsafe { (cstr(expr), cstr(file), cstr(func)) };
    slate_rt::eprintln!(
        "{}:{line}: {}: assertion '{}' failed",
        slate_rt::lossy(f),
        slate_rt::lossy(func),
        slate_rt::lossy(e)
    );
    abort()
}

// --- the environment ----------------------------------------------------------

/// The C `environ`: a NULL-terminated array of `NAME=value` strings. It
/// starts as the array on the initial stack; the first change copies it
/// into [`ENV`].
#[allow(non_upper_case_globals)] // C's name.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static environ: AtomicPtr<*mut c_char> = AtomicPtr::new(null_mut());

/// The environment once changed: the strings (owned with malloc) and
/// the pointer array `environ` points at.
/// (Kept as addresses: pointers are not `Send`.)
static ENV: Mutex<Option<Vec<usize>>> = Mutex::new(None);

/// Point `environ` at the initial environment.
///
/// # Safety
///
/// `envp` must be the NULL-terminated array from the initial stack.
pub unsafe fn init_environ(envp: *mut *mut c_char) {
    environ.store(envp, Ordering::Relaxed);
}

/// The environment's strings.
fn entries() -> Vec<*mut c_char> {
    let mut out = Vec::new();
    let mut p = environ.load(Ordering::Relaxed);
    if p.is_null() {
        return out;
    }
    // SAFETY: `environ` is NULL-terminated (ours, or the initial stack's).
    unsafe {
        while !(*p).is_null() {
            out.push(*p);
            p = p.add(1);
        }
    }
    out
}

/// The value of `name` in entry `e`, if it is that variable's.
///
/// # Safety
///
/// `e` must be a NUL-terminated string.
unsafe fn value_of(e: *mut c_char, name: &[u8]) -> Option<*mut c_char> {
    // SAFETY: Forwarded from the caller.
    let s = unsafe { cstr(e) };
    (s.len() > name.len() && s.starts_with(name) && s[name.len()] == b'=').then(|| e.wrapping_add(name.len() + 1))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    // SAFETY: `name` is NUL-terminated.
    let name = unsafe { cstr(name) };
    // SAFETY: Entries are NUL-terminated.
    entries().into_iter().find_map(|e| unsafe { value_of(e, name) }).unwrap_or(null_mut())
}

/// Replace the environment with `list` (pointers to malloc'd strings).
fn store(list: Vec<*mut c_char>) {
    let mut list: Vec<usize> = list.into_iter().map(|p| p as usize).collect();
    list.push(0);
    let mut env = ENV.lock();
    environ.store(list.as_mut_ptr() as *mut *mut c_char, Ordering::Relaxed);
    *env = Some(list);
}

fn bad_name(name: &[u8]) -> bool {
    name.is_empty() || name.contains(&b'=')
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    // SAFETY: Both are NUL-terminated.
    let (n, v) = unsafe { (cstr(name), cstr(value)) };
    if bad_name(n) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    let mut list = entries();
    // SAFETY: Entries are NUL-terminated.
    let at = list.iter().position(|&e| unsafe { value_of(e, n) }.is_some());
    if at.is_some() && overwrite == 0 {
        return 0;
    }
    let entry = malloc(n.len() + v.len() + 2) as *mut u8;
    if entry.is_null() {
        return -1;
    }
    // SAFETY: The new block holds NAME=value and a NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(n.as_ptr(), entry, n.len());
        *entry.add(n.len()) = b'=';
        core::ptr::copy_nonoverlapping(v.as_ptr(), entry.add(n.len() + 1), v.len());
        *entry.add(n.len() + 1 + v.len()) = 0;
    }
    // The old string may belong to the caller (putenv-style) or the
    // initial stack, so it is not freed.
    match at {
        Some(i) => list[i] = entry as *mut c_char,
        None => list.push(entry as *mut c_char),
    }
    store(list);
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    // SAFETY: `name` is NUL-terminated.
    let n = unsafe { cstr(name) };
    if bad_name(n) {
        set_errno(Errno::EINVAL);
        return -1;
    }
    let mut list = entries();
    // SAFETY: Entries are NUL-terminated.
    list.retain(|&e| unsafe { value_of(e, n) }.is_none());
    store(list);
    0
}

/// The environment as slate-rt wants it (for exec).
pub(crate) fn env_vec() -> Vec<Vec<u8>> {
    // SAFETY: Entries are NUL-terminated.
    entries().into_iter().map(|e| unsafe { cstr(e) }.to_vec()).collect()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    if command.is_null() {
        return 1; // A shell is available.
    }
    // SAFETY: `command` is NUL-terminated.
    let cmd = unsafe { cstr(command) }.to_vec();
    crate::stdio::flush_all();
    let pid = match slate_rt::process::fork() {
        Ok(p) => p,
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    if pid == 0 {
        let argv = [b"sh".to_vec(), b"-c".to_vec(), cmd];
        slate_rt::process::execve(b"/bin/sh", &argv, &env_vec());
        slate_rt::process::exit_now(127);
    }
    match slate_rt::process::wait(pid, 0) {
        Ok((_, status)) => status,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

// --- numbers ----------------------------------------------------------------

/// Parse an integer as strtol(3) does: white space, a sign, an optional
/// `0x`/`0` prefix for bases 16 and 0, then digits. Returns the
/// magnitude (saturated, with an overflow flag), the sign and the bytes
/// used (0 if there were no digits).
fn parse(s: &[u8], base: c_int) -> Option<(u64, bool, bool, usize)> {
    if base != 0 && !(2..=36).contains(&base) {
        return None;
    }
    let mut i = 0;
    while s.get(i).is_some_and(|&c| c == b' ' || (b'\t'..=b'\r').contains(&c)) {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c) = s.get(i)
        && (c == b'+' || c == b'-')
    {
        neg = c == b'-';
        i += 1;
    }
    let mut base = base as u64;
    let hex_prefix = s.get(i) == Some(&b'0')
        && matches!(s.get(i + 1), Some(b'x' | b'X'))
        && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
    if (base == 0 || base == 16) && hex_prefix {
        base = 16;
        i += 2;
    } else if base == 0 {
        base = if s.get(i) == Some(&b'0') { 8 } else { 10 };
    }
    let (mut v, mut overflow, start) = (0u64, false, i);
    while let Some(d) = s.get(i).and_then(|&c| (c as char).to_digit(36)).filter(|&d| u64::from(d) < base) {
        match v.checked_mul(base).and_then(|x| x.checked_add(u64::from(d))) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return Some((0, false, false, 0));
    }
    Some((if overflow { u64::MAX } else { v }, neg, overflow, i))
}

/// strtol's core for a signed type with the given limits.
///
/// # Safety
///
/// `s` must be NUL-terminated; `end`, if not null, writable.
unsafe fn strto_signed(s: *const c_char, end: *mut *mut c_char, base: c_int, min: i64, max: i64) -> i64 {
    // SAFETY: Forwarded from the caller.
    let text = unsafe { cstr(s) };
    let Some((v, neg, overflow, used)) = parse(text, base) else {
        set_errno(Errno::EINVAL);
        return 0;
    };
    if !end.is_null() {
        // SAFETY: The caller provided a place for the end pointer.
        unsafe { *end = s.wrapping_add(used) as *mut c_char };
    }
    let limit = if neg { min.unsigned_abs() } else { max as u64 };
    if overflow || v > limit {
        set_errno(Errno::ERANGE);
        return if neg { min } else { max };
    }
    if neg { (v as i64).wrapping_neg() } else { v as i64 }
}

/// strtoul's core: a minus sign negates the value (as C says).
///
/// # Safety
///
/// As for [`strto_signed`].
unsafe fn strto_unsigned(s: *const c_char, end: *mut *mut c_char, base: c_int) -> u64 {
    // SAFETY: Forwarded from the caller.
    let text = unsafe { cstr(s) };
    let Some((v, neg, overflow, used)) = parse(text, base) else {
        set_errno(Errno::EINVAL);
        return 0;
    };
    if !end.is_null() {
        // SAFETY: The caller provided a place for the end pointer.
        unsafe { *end = s.wrapping_add(used) as *mut c_char };
    }
    if overflow {
        set_errno(Errno::ERANGE);
        return u64::MAX;
    }
    if neg { v.wrapping_neg() } else { v }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtol(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_long {
    // SAFETY: C's contract for strtol.
    unsafe { strto_signed(s, end, base, i64::MIN, i64::MAX) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtoll(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_longlong {
    // SAFETY: C's contract for strtoll.
    unsafe { strto_signed(s, end, base, i64::MIN, i64::MAX) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtoul(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulong {
    // SAFETY: C's contract for strtoul.
    unsafe { strto_unsigned(s, end, base) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtoull(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulonglong {
    // SAFETY: C's contract for strtoull.
    unsafe { strto_unsigned(s, end, base) }
}

/// strtod and strtof (C11 7.22.1.3), correctly rounded ([`crate::float`]).
unsafe fn strto_float(s: *const c_char, end: *mut *mut c_char, f: crate::float::Format) -> u64 {
    // SAFETY: C passes a NUL-terminated string.
    let text = unsafe { crate::cstr(s) };
    let (bits, used, range) = crate::float::parse(text, f);
    if !end.is_null() {
        // SAFETY: C passes room for the end pointer.
        unsafe { *end = s.wrapping_add(used) as *mut c_char };
    }
    if range {
        set_errno(Errno::ERANGE);
    }
    bits
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(s: *const c_char, end: *mut *mut c_char) -> f64 {
    // SAFETY: C's contract for strtod.
    f64::from_bits(unsafe { strto_float(s, end, crate::float::DOUBLE) })
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(s: *const c_char, end: *mut *mut c_char) -> f32 {
    // SAFETY: C's contract for strtof.
    f32::from_bits(unsafe { strto_float(s, end, crate::float::SINGLE) } as u32)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn atof(s: *const c_char) -> f64 {
    // SAFETY: `s` is NUL-terminated.
    unsafe { strtod(s, null_mut()) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    // SAFETY: `s` is NUL-terminated.
    unsafe { strto_signed(s, null_mut(), 10, i64::from(i32::MIN), i64::from(i32::MAX)) as c_int }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    // SAFETY: `s` is NUL-terminated.
    unsafe { strtol(s, null_mut(), 10) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    // SAFETY: `s` is NUL-terminated.
    unsafe { strtol(s, null_mut(), 10) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn abs(x: c_int) -> c_int {
    x.wrapping_abs()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn labs(x: c_long) -> c_long {
    x.wrapping_abs()
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn llabs(x: c_longlong) -> c_longlong {
    x.wrapping_abs()
}

// --- pseudo-random numbers --------------------------------------------------

/// rand(3)'s state: a 64-bit linear congruential generator (Knuth's
/// MMIX constants), the top 31 bits returned.
static SEED: AtomicU64 = AtomicU64::new(1);

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn srand(seed: c_uint) {
    SEED.store(u64::from(seed), Ordering::Relaxed);
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn rand() -> c_int {
    let next =
        SEED.load(Ordering::Relaxed).wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
    SEED.store(next, Ordering::Relaxed);
    (next >> 33) as c_int
}

// --- sorting and searching ------------------------------------------------

type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// Swap elements `i` and `j` of `size` bytes.
///
/// # Safety
///
/// Both must be inside the array.
unsafe fn swap(base: *mut u8, size: usize, i: usize, j: usize) {
    if i != j {
        // SAFETY: Distinct elements inside the array.
        unsafe { core::ptr::swap_nonoverlapping(base.add(i * size), base.add(j * size), size) };
    }
}

/// qsort(3) as a heap sort: O(n log n), no allocation, no recursion.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(base: *mut c_void, n: usize, size: usize, cmp: Compare) {
    let b = base as *mut u8;
    // SAFETY: C guarantees `n` elements of `size` bytes at `base`.
    let less =
        |i: usize, j: usize| unsafe { cmp(b.add(i * size) as *const c_void, b.add(j * size) as *const c_void) < 0 };
    let sift = |mut root: usize, end: usize| {
        loop {
            let mut child = 2 * root + 1;
            if child >= end {
                break;
            }
            if child + 1 < end && less(child, child + 1) {
                child += 1;
            }
            if !less(root, child) {
                break;
            }
            // SAFETY: Both indices are below `end` <= `n`.
            unsafe { swap(b, size, root, child) };
            root = child;
        }
    };
    if n < 2 || size == 0 {
        return;
    }
    for start in (0..n / 2).rev() {
        sift(start, n);
    }
    for end in (1..n).rev() {
        // SAFETY: Both indices are below `n`.
        unsafe { swap(b, size, 0, end) };
        sift(0, end);
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    n: usize,
    size: usize,
    cmp: Compare,
) -> *mut c_void {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let p = (base as *const u8).wrapping_add(mid * size) as *const c_void;
        // SAFETY: `mid` is inside the array.
        match unsafe { cmp(key, p) } {
            0 => return p as *mut c_void,
            c if c < 0 => hi = mid,
            _ => lo = mid + 1,
        }
    }
    null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions() {
        let mut end = null_mut();
        // SAFETY: C-string literals.
        unsafe {
            assert_eq!(strtol(c"  -42x".as_ptr(), &mut end, 10), -42);
            assert_eq!(*end as u8, b'x');
            assert_eq!(strtol(c"0x1F".as_ptr(), null_mut(), 0), 31);
            assert_eq!(strtol(c"017".as_ptr(), null_mut(), 0), 15);
            assert_eq!(strtoul(c"ff".as_ptr(), null_mut(), 16), 255);
            assert_eq!(strtol(c"99999999999999999999".as_ptr(), null_mut(), 10), i64::MAX);
            assert_eq!(crate::errno(), Errno::ERANGE.0);
            assert_eq!(strtol(c"zz".as_ptr(), &mut end, 10), 0);
            assert_eq!(atoi(c"123abc".as_ptr()), 123);
        }
    }

    unsafe extern "C" fn by_value(a: *const c_void, b: *const c_void) -> c_int {
        // SAFETY: The tests sort i32s.
        unsafe { (*(a as *const i32)).cmp(&*(b as *const i32)) as c_int }
    }

    #[test]
    fn sort_and_search() {
        let mut v = [5i32, -1, 3, 3, 9, 0, 2];
        // SAFETY: A valid i32 array and comparator.
        unsafe {
            qsort(v.as_mut_ptr() as *mut c_void, v.len(), 4, by_value);
            assert_eq!(v, [-1, 0, 2, 3, 3, 5, 9]);
            let key = 5i32;
            let p = bsearch(&key as *const i32 as *const c_void, v.as_ptr() as *const c_void, v.len(), 4, by_value);
            assert_eq!(*(p as *const i32), 5);
        }
    }

    #[test]
    fn memory() {
        let p = malloc(10) as *mut u8;
        // SAFETY: Blocks from this allocator.
        unsafe {
            p.write_bytes(7, 10);
            let q = realloc(p as *mut c_void, 100) as *mut u8;
            assert_eq!(*q.add(9), 7);
            free(q as *mut c_void);
            let z = calloc(4, 4) as *const u32;
            assert_eq!(*z.add(3), 0);
            free(z as *mut c_void);
        }
    }
}
