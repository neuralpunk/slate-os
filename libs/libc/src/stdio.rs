// SPDX-License-Identifier: MIT OR Apache-2.0

//! <stdio.h> (C11 7.21): streams over descriptors, with buffering
//! (standard output is line-buffered on a terminal and fully buffered
//! otherwise; standard error is unbuffered), and the printf family.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;

use slate_rt::sync::Mutex;
use slate_rt::{Errno, io};

use crate::{cstr, ret, set_errno};

const EOF: c_int = -1;
const BUF: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Buffering {
    None,
    Line,
    Full,
}

struct State {
    fd: i32,
    /// Bytes written but not yet passed to the descriptor.
    out: Vec<u8>,
    /// Bytes read ahead, and how many of them were consumed.
    input: Vec<u8>,
    pos: usize,
    eof: bool,
    error: bool,
    /// Decided on first use for standard output (terminal or not).
    buffering: Option<Buffering>,
}

/// A C `FILE`.
pub struct File {
    state: Mutex<State>,
}

impl File {
    const fn new(fd: i32, buffering: Option<Buffering>) -> File {
        File {
            state: Mutex::new(State {
                fd,
                out: Vec::new(),
                input: Vec::new(),
                pos: 0,
                eof: false,
                error: false,
                buffering,
            }),
        }
    }
}

impl State {
    fn buffering(&mut self) -> Buffering {
        *self
            .buffering
            .get_or_insert_with(|| if slate_rt::term::isatty(self.fd) { Buffering::Line } else { Buffering::Full })
    }

    fn flush(&mut self) -> bool {
        if self.out.is_empty() {
            return true;
        }
        let r = io::write_all(self.fd, &self.out);
        self.out.clear();
        if let Err(e) = r {
            self.error = true;
            set_errno(e);
            return false;
        }
        true
    }

    fn write(&mut self, data: &[u8]) -> bool {
        // Reading ahead and writing do not mix: drop what was read ahead.
        if self.pos < self.input.len() {
            let back = self.input.len() - self.pos;
            let _ = io::lseek(self.fd, -(back as i64), 1);
        }
        self.input.clear();
        self.pos = 0;
        self.out.extend_from_slice(data);
        match self.buffering() {
            Buffering::None => self.flush(),
            Buffering::Line if data.contains(&b'\n') => self.flush(),
            _ if self.out.len() >= BUF => self.flush(),
            _ => true,
        }
    }

    /// The next byte, or None at end of file or on error.
    fn getc(&mut self) -> Option<u8> {
        if self.pos == self.input.len() {
            if !self.flush() {
                return None;
            }
            // Reading from a terminal flushes standard output first, so
            // prompts appear.
            if self.fd == 0 {
                STDOUT_FILE.state.lock().flush();
            }
            self.input.resize(BUF, 0);
            self.pos = 0;
            match io::read(self.fd, &mut self.input) {
                Ok(0) => {
                    self.input.clear();
                    self.eof = true;
                    return None;
                }
                Ok(n) => self.input.truncate(n),
                Err(e) => {
                    self.input.clear();
                    self.error = true;
                    set_errno(e);
                    return None;
                }
            }
        }
        let b = self.input[self.pos];
        self.pos += 1;
        Some(b)
    }
}

static STDIN_FILE: File = File::new(0, Some(Buffering::Full));
static STDOUT_FILE: File = File::new(1, None);
static STDERR_FILE: File = File::new(2, Some(Buffering::None));

/// A FILE pointer as C sees it.
#[repr(transparent)]
pub struct FilePtr(*const File);

// SAFETY: The streams synchronise through their locks.
unsafe impl Sync for FilePtr {}

#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static stdin: FilePtr = FilePtr(&STDIN_FILE);
#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static stdout: FilePtr = FilePtr(&STDOUT_FILE);
#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static stderr: FilePtr = FilePtr(&STDERR_FILE);

/// Streams opened with fopen, for flushing at exit.
static OPEN: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Flush every stream (exit, abort, fork for system).
pub fn flush_all() {
    STDOUT_FILE.state.lock().flush();
    STDERR_FILE.state.lock().flush();
    for &f in OPEN.lock().iter() {
        // SAFETY: Streams stay in OPEN until fclose frees them.
        unsafe { &*(f as *const File) }.state.lock().flush();
    }
}

/// The stream behind a C pointer.
///
/// # Safety
///
/// `f` must be a stream from this library.
unsafe fn file<'a>(f: *mut File) -> &'a File {
    // SAFETY: Forwarded from the caller.
    unsafe { &*f }
}

/// fopen(3) modes as open(2) flags (slate-rt's O_* values).
fn mode_flags(mode: &[u8]) -> Option<u32> {
    use slate_rt::fs::*;
    let plus = mode.contains(&b'+');
    let base = match mode.first()? {
        b'r' => {
            if plus {
                O_RDWR
            } else {
                O_RDONLY
            }
        }
        b'w' => O_CREAT | O_TRUNC | if plus { O_RDWR } else { O_WRONLY },
        b'a' => O_CREAT | O_APPEND | if plus { O_RDWR } else { O_WRONLY },
        _ => return None,
    };
    let excl = if mode.contains(&b'x') { O_EXCL } else { 0 };
    let cloexec = if mode.contains(&b'e') { O_CLOEXEC } else { 0 };
    Some(base | excl | cloexec)
}

fn new_stream(fd: i32) -> *mut File {
    let f = Box::into_raw(Box::new(File::new(
        fd,
        Some(if slate_rt::term::isatty(fd) { Buffering::Line } else { Buffering::Full }),
    )));
    OPEN.lock().push(f as usize);
    f
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut File {
    // SAFETY: Both are NUL-terminated.
    let (p, m) = unsafe { (cstr(path), cstr(mode)) };
    let Some(flags) = mode_flags(m) else {
        set_errno(Errno::EINVAL);
        return null_mut();
    };
    match slate_rt::fs::open(p, flags, 0o666) {
        Ok(fd) => new_stream(fd),
        Err(e) => {
            set_errno(e);
            null_mut()
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut File {
    // SAFETY: `mode` is NUL-terminated.
    if mode_flags(unsafe { cstr(mode) }).is_none() {
        set_errno(Errno::EINVAL);
        return null_mut();
    }
    new_stream(fd)
}

fn is_standard(f: *mut File) -> bool {
    [&STDIN_FILE, &STDOUT_FILE, &STDERR_FILE].iter().any(|s| core::ptr::eq(*s, f))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(f: *mut File) -> c_int {
    let (ok, fd) = {
        // SAFETY: `f` is a stream from fopen (or a standard one).
        let mut s = unsafe { file(f) }.state.lock();
        (s.flush(), s.fd)
    };
    let closed = slate_rt::io::close(fd);
    if !is_standard(f) {
        OPEN.lock().retain(|&p| p != f as usize);
        // SAFETY: Made by Box::into_raw in new_stream; no longer listed.
        drop(unsafe { Box::from_raw(f) });
    }
    if !ok {
        return EOF;
    }
    match closed {
        Ok(()) => 0,
        Err(e) => {
            set_errno(e);
            EOF
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(f: *mut File) -> c_int {
    if f.is_null() {
        flush_all();
        return 0;
    }
    // SAFETY: A stream from this library.
    if unsafe { file(f) }.state.lock().flush() { 0 } else { EOF }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(buf: *const c_void, size: usize, n: usize, f: *mut File) -> usize {
    let Some(total) = size.checked_mul(n) else { return 0 };
    if total == 0 {
        return 0;
    }
    // SAFETY: C guarantees `total` readable bytes; `f` is a stream.
    let ok = unsafe { file(f).state.lock().write(core::slice::from_raw_parts(buf as *const u8, total)) };
    if ok { n } else { 0 }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fread(buf: *mut c_void, size: usize, n: usize, f: *mut File) -> usize {
    let Some(total) = size.checked_mul(n) else { return 0 };
    if total == 0 {
        return 0;
    }
    // SAFETY: A stream from this library; `buf` holds `total` bytes.
    let mut s = unsafe { file(f) }.state.lock();
    let out = buf as *mut u8;
    let mut done = 0;
    while done < total {
        let Some(b) = s.getc() else { break };
        // SAFETY: `done < total`.
        unsafe { *out.add(done) = b };
        done += 1;
    }
    done / size
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc(f: *mut File) -> c_int {
    // SAFETY: A stream from this library.
    unsafe { file(f) }.state.lock().getc().map_or(EOF, c_int::from)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn getc(f: *mut File) -> c_int {
    // SAFETY: As for fgetc.
    unsafe { fgetc(f) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn getchar() -> c_int {
    STDIN_FILE.state.lock().getc().map_or(EOF, c_int::from)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, f: *mut File) -> c_int {
    if c == EOF {
        return EOF;
    }
    // SAFETY: A stream from this library.
    let mut s = unsafe { file(f) }.state.lock();
    if s.pos > 0 {
        s.pos -= 1;
        let p = s.pos;
        s.input[p] = c as u8;
    } else {
        s.input.insert(0, c as u8);
    }
    s.eof = false;
    c
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fgets(buf: *mut c_char, n: c_int, f: *mut File) -> *mut c_char {
    if n <= 0 {
        return null_mut();
    }
    // SAFETY: A stream from this library; `buf` holds `n` bytes.
    let mut s = unsafe { file(f) }.state.lock();
    let mut i = 0;
    while i + 1 < n as usize {
        let Some(b) = s.getc() else { break };
        // SAFETY: `i < n - 1`.
        unsafe { *buf.add(i) = b as c_char };
        i += 1;
        if b == b'\n' {
            break;
        }
    }
    if i == 0 {
        return null_mut();
    }
    // SAFETY: `i <= n - 1`.
    unsafe { *buf.add(i) = 0 };
    buf
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut File) -> c_int {
    // SAFETY: A stream from this library.
    if unsafe { file(f) }.state.lock().write(&[c as u8]) { c & 0xFF } else { EOF }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn putc(c: c_int, f: *mut File) -> c_int {
    // SAFETY: As for fputc.
    unsafe { fputc(c, f) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn putchar(c: c_int) -> c_int {
    if STDOUT_FILE.state.lock().write(&[c as u8]) { c & 0xFF } else { EOF }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut File) -> c_int {
    // SAFETY: `s` is NUL-terminated; `f` a stream.
    if unsafe { file(f).state.lock().write(cstr(s)) } { 0 } else { EOF }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    let mut st = STDOUT_FILE.state.lock();
    // SAFETY: `s` is NUL-terminated.
    if st.write(unsafe { cstr(s) }) && st.write(b"\n") { 0 } else { EOF }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(f: *mut File, offset: c_long, whence: c_int) -> c_int {
    // SAFETY: A stream from this library.
    let mut s = unsafe { file(f) }.state.lock();
    if !s.flush() {
        return -1;
    }
    // A relative seek counts from the reader's position, not the
    // descriptor's (which is ahead by what was read ahead).
    let offset = if whence == 1 { offset - (s.input.len() - s.pos) as c_long } else { offset };
    s.input.clear();
    s.pos = 0;
    s.eof = false;
    let fd = s.fd;
    ret(io::lseek(fd, offset, whence as u32).map(|_| 0))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(f: *mut File) -> c_long {
    // SAFETY: A stream from this library.
    let s = unsafe { file(f) }.state.lock();
    match io::lseek(s.fd, 0, 1) {
        Ok(p) => p as c_long - (s.input.len() - s.pos) as c_long + s.out.len() as c_long,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn rewind(f: *mut File) {
    // SAFETY: A stream from this library.
    unsafe {
        fseek(f, 0, 0);
        file(f).state.lock().error = false;
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn feof(f: *mut File) -> c_int {
    // SAFETY: A stream from this library.
    c_int::from(unsafe { file(f) }.state.lock().eof)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(f: *mut File) -> c_int {
    // SAFETY: A stream from this library.
    c_int::from(unsafe { file(f) }.state.lock().error)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr(f: *mut File) {
    // SAFETY: A stream from this library.
    let mut s = unsafe { file(f) }.state.lock();
    s.eof = false;
    s.error = false;
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(f: *mut File) -> c_int {
    // SAFETY: A stream from this library.
    unsafe { file(f) }.state.lock().fd
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn perror(s: *const c_char) {
    let msg = Errno(crate::errno()).message();
    let mut e = STDERR_FILE.state.lock();
    // SAFETY: `s` is null or NUL-terminated.
    let prefix = if s.is_null() { &b""[..] } else { unsafe { cstr(s) } };
    if !prefix.is_empty() {
        e.write(prefix);
        e.write(b": ");
    }
    e.write(msg.as_bytes());
    e.write(b"\n");
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    // SAFETY: `path` is NUL-terminated.
    let p = unsafe { cstr(path) };
    match slate_rt::fs::unlink(p) {
        Err(Errno::EISDIR) | Err(Errno::EPERM) => ret(slate_rt::fs::rmdir(p).map(|_| 0)),
        r => ret(r.map(|_| 0)),
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
    // SAFETY: Both are NUL-terminated.
    ret(unsafe { slate_rt::fs::rename(cstr(from), cstr(to)) }.map(|_| 0))
}

// --- the printf family -------------------------------------------------------

/// Format with a C argument list.
///
/// # Safety
///
/// `fmt` is NUL-terminated and the arguments match it.
unsafe fn render(fmt: *const c_char, ap: &mut VaList<'_>) -> Vec<u8> {
    // SAFETY: Forwarded from the caller.
    unsafe { crate::format::format(cstr(fmt), ap) }
}

fn length(out: &[u8]) -> c_int {
    c_int::try_from(out.len()).unwrap_or(c_int::MAX)
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vfprintf(f: *mut File, fmt: *const c_char, mut ap: VaList<'_>) -> c_int {
    // SAFETY: C's printf contract; `f` is a stream.
    unsafe {
        let out = render(fmt, &mut ap);
        if file(f).state.lock().write(&out) { length(&out) } else { -1 }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(fmt: *const c_char, ap: VaList<'_>) -> c_int {
    // SAFETY: As for vfprintf.
    unsafe { vfprintf(stdout.0 as *mut File, fmt, ap) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vdprintf(fd: c_int, fmt: *const c_char, mut ap: VaList<'_>) -> c_int {
    // SAFETY: C's printf contract.
    let out = unsafe { render(fmt, &mut ap) };
    ret(io::write_all(fd, &out).map(|_| length(&out)))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vsnprintf(s: *mut c_char, n: usize, fmt: *const c_char, mut ap: VaList<'_>) -> c_int {
    // SAFETY: C's printf contract; `s` holds `n` bytes.
    unsafe {
        let out = render(fmt, &mut ap);
        if n > 0 {
            let k = out.len().min(n - 1);
            core::ptr::copy_nonoverlapping(out.as_ptr(), s as *mut u8, k);
            *s.add(k) = 0;
        }
        length(&out)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vsprintf(s: *mut c_char, fmt: *const c_char, ap: VaList<'_>) -> c_int {
    // SAFETY: C guarantees `s` is large enough.
    unsafe { vsnprintf(s, usize::MAX, fmt, ap) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn printf(fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's printf contract.
    unsafe {
        let out = render(fmt, &mut args);
        if STDOUT_FILE.state.lock().write(&out) { length(&out) } else { -1 }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fprintf(f: *mut File, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's printf contract; `f` is a stream.
    unsafe {
        let out = render(fmt, &mut args);
        if file(f).state.lock().write(&out) { length(&out) } else { -1 }
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn dprintf(fd: c_int, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's printf contract.
    let out = unsafe { render(fmt, &mut args) };
    ret(io::write_all(fd, &out).map(|_| length(&out)))
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's printf contract; `s` holds `n` bytes.
    unsafe {
        let out = render(fmt, &mut args);
        if n > 0 {
            let k = out.len().min(n - 1);
            core::ptr::copy_nonoverlapping(out.as_ptr(), s as *mut u8, k);
            *s.add(k) = 0;
        }
        length(&out)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sprintf(s: *mut c_char, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C guarantees `s` is large enough.
    unsafe {
        let out = render(fmt, &mut args);
        core::ptr::copy_nonoverlapping(out.as_ptr(), s as *mut u8, out.len());
        *s.add(out.len()) = 0;
        length(&out)
    }
}

// --- scanf --------------------------------------------------------------------

/// A stream as scanf's source: one byte of lookahead in its read-ahead
/// buffer, which is where an unmatched byte stays.
struct StreamSource<'a>(&'a mut State);

impl crate::scanf::Source for StreamSource<'_> {
    fn peek(&mut self) -> Option<u8> {
        let c = self.0.getc()?;
        self.0.pos -= 1;
        Some(c)
    }
    fn bump(&mut self) {
        self.0.pos += 1;
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vfscanf(f: *mut File, fmt: *const c_char, mut ap: VaList<'_>) -> c_int {
    // SAFETY: C's scanf contract; `f` is a stream.
    unsafe {
        let mut s = file(f).state.lock();
        crate::scanf::scan(cstr(fmt), &mut StreamSource(&mut s), &mut ap)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vscanf(fmt: *const c_char, ap: VaList<'_>) -> c_int {
    // SAFETY: As for vfscanf.
    unsafe { vfscanf(stdin.0 as *mut File, fmt, ap) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn vsscanf(s: *const c_char, fmt: *const c_char, mut ap: VaList<'_>) -> c_int {
    // SAFETY: C's scanf contract; `s` is NUL-terminated.
    unsafe { crate::scanf::scan(cstr(fmt), &mut crate::scanf::Bytes { s: cstr(s), pos: 0 }, &mut ap) }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn fscanf(f: *mut File, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's scanf contract; `f` is a stream.
    unsafe {
        let mut s = file(f).state.lock();
        crate::scanf::scan(cstr(fmt), &mut StreamSource(&mut s), &mut args)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn scanf(fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's scanf contract.
    unsafe {
        let mut s = STDIN_FILE.state.lock();
        crate::scanf::scan(cstr(fmt), &mut StreamSource(&mut s), &mut args)
    }
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn sscanf(s: *const c_char, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: C's scanf contract; `s` is NUL-terminated.
    unsafe { crate::scanf::scan(cstr(fmt), &mut crate::scanf::Bytes { s: cstr(s), pos: 0 }, &mut args) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fopen_modes() {
        use slate_rt::fs::*;
        assert_eq!(mode_flags(b"r"), Some(O_RDONLY));
        assert_eq!(mode_flags(b"w+"), Some(O_CREAT | O_TRUNC | O_RDWR));
        assert_eq!(mode_flags(b"ae"), Some(O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC));
        assert_eq!(mode_flags(b"q"), None);
    }
}
