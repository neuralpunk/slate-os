// SPDX-License-Identifier: MIT OR Apache-2.0

//! File descriptor I/O, buffered standard output, and line reading.

use alloc::vec::Vec;
use core::fmt;

use slate_sync::SpinLock;

use crate::errno::{Errno, Result};
use crate::sys;
use slate_abi::nr;

pub const STDIN: i32 = 0;
pub const STDOUT: i32 = 1;
pub const STDERR: i32 = 2;

pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize> {
    loop {
        match crate::syscall!(sys::pick(sys::READ, nr::READ), fd, buf.as_mut_ptr(), buf.len()) {
            Err(Errno::EINTR) => continue,
            r => return r,
        }
    }
}

/// One read(2) that a caught signal may interrupt (EINTR): for programs
/// that act on signals while they wait (dd's SIGUSR1).
pub fn read_interruptible(fd: i32, buf: &mut [u8]) -> Result<usize> {
    crate::syscall!(sys::pick(sys::READ, nr::READ), fd, buf.as_mut_ptr(), buf.len())
}

pub fn write(fd: i32, buf: &[u8]) -> Result<usize> {
    loop {
        match crate::syscall!(sys::pick(sys::WRITE, nr::WRITE), fd, buf.as_ptr(), buf.len()) {
            Err(Errno::EINTR) => continue,
            r => return r,
        }
    }
}

pub fn write_all(fd: i32, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = write(fd, buf)?;
        if n == 0 {
            return Err(Errno::EIO);
        }
        buf = &buf[n..];
    }
    Ok(())
}

/// Read until end of file.
pub fn read_to_end(fd: i32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        let n = read(fd, &mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Read at `offset` without moving the file position (pread(2)).
pub fn pread(fd: i32, buf: &mut [u8], offset: u64) -> Result<usize> {
    loop {
        match crate::syscall!(sys::pick(sys::PREAD64, nr::PREAD), fd, buf.as_mut_ptr(), buf.len(), offset) {
            Err(Errno::EINTR) => {}
            r => return r,
        }
    }
}

/// Write at `offset` without moving the file position (pwrite(2)).
pub fn pwrite(fd: i32, buf: &[u8], offset: u64) -> Result<usize> {
    loop {
        match crate::syscall!(sys::pick(sys::PWRITE64, nr::PWRITE), fd, buf.as_ptr(), buf.len(), offset) {
            Err(Errno::EINTR) => {}
            r => return r,
        }
    }
}

/// ioctl(2) with a pointer or integer argument.
pub fn ioctl(fd: i32, request: u32, arg: usize) -> Result<usize> {
    crate::syscall!(sys::pick(sys::IOCTL, nr::IOCTL), fd, request as usize, arg)
}

pub fn close(fd: i32) -> Result<()> {
    crate::syscall!(sys::pick(sys::CLOSE, nr::CLOSE), fd).map(|_| ())
}

/// lseek(2)'s `whence` (musl `unistd.h`).
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

pub fn lseek(fd: i32, off: i64, whence: u32) -> Result<u64> {
    crate::syscall!(sys::pick(sys::LSEEK, nr::SEEK), fd, off, whence).map(|n| n as u64)
}

/// A buffered writer on a descriptor.
#[derive(Debug)]
pub struct Writer {
    fd: i32,
    buf: Vec<u8>,
    /// Flush at every newline (terminals).
    line: bool,
    /// A write failed (EPIPE...): stop trying and report it at exit.
    pub failed: Option<Errno>,
}

impl Writer {
    pub const fn new(fd: i32) -> Writer {
        Writer { fd, buf: Vec::new(), line: false, failed: None }
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        self.buf.extend_from_slice(b);
        let has_nl = self.line && b.contains(&b'\n');
        if self.buf.len() >= 32 * 1024 || has_nl {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        if self.failed.is_none()
            && !self.buf.is_empty()
            && let Err(e) = write_all(self.fd, &self.buf)
        {
            self.failed = Some(e);
        }
        self.buf.clear();
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

pub static STDOUT_W: SpinLock<Writer> = SpinLock::new(Writer::new(STDOUT));

/// Write bytes to standard output (buffered; line-buffered on a terminal).
pub fn out(b: &[u8]) {
    let mut w = STDOUT_W.lock();
    if !w.line && w.buf.is_empty() {
        w.line = crate::term::isatty(STDOUT);
    }
    w.write_bytes(b);
}

pub fn flush_stdout() -> Option<Errno> {
    let mut w = STDOUT_W.lock();
    w.flush();
    w.failed
}

/// Flush standard output and clear its error state (a shell's built-ins
/// share one writer while descriptor 1 changes under it): the error the
/// output since the last call ran into, if any.
pub fn reset_stdout() -> Option<Errno> {
    let mut w = STDOUT_W.lock();
    w.flush();
    w.line = false;
    w.failed.take()
}

/// Write bytes to standard error (unbuffered).
pub fn err(b: &[u8]) {
    let _ = write_all(STDERR, b);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut w = STDOUT_W.lock();
    if !w.line && w.buf.is_empty() {
        w.line = crate::term::isatty(STDOUT);
    }
    let _ = fmt::write(&mut *w, args);
}

#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments<'_>) {
    let mut w = Writer::new(STDERR);
    let _ = fmt::write(&mut w, args);
    w.flush();
}

#[macro_export]
macro_rules! print {
    ($($t:tt)*) => { $crate::io::_print(format_args!($($t)*)) };
}
#[macro_export]
macro_rules! println {
    () => { $crate::io::out(b"\n") };
    ($($t:tt)*) => {{ $crate::io::_print(format_args!($($t)*)); $crate::io::out(b"\n"); }};
}
#[macro_export]
macro_rules! eprint {
    ($($t:tt)*) => { $crate::io::_eprint(format_args!($($t)*)) };
}
#[macro_export]
macro_rules! eprintln {
    ($($t:tt)*) => { $crate::io::_eprint(format_args!("{}\n", format_args!($($t)*))) };
}

/// The first `b` in `h`, eight bytes at a time (the lines of big files
/// are found with it).
pub fn find_byte(b: u8, h: &[u8]) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let rep = LO * u64::from(b);
    let mut i = 0;
    while i + 8 <= h.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&h[i..i + 8]);
        // The bytes equal to `b` become zero; the lowest flagged is the first.
        let x = u64::from_le_bytes(w) ^ rep;
        let m = x.wrapping_sub(LO) & !x & HI;
        if m != 0 {
            return Some(i + (m.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    h[i..].iter().position(|&c| c == b).map(|p| i + p)
}

/// Buffered reading from a descriptor, by lines or bytes.
#[derive(Debug)]
pub struct Reader {
    fd: i32,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl Reader {
    pub fn new(fd: i32) -> Reader {
        Reader { fd, buf: Vec::new(), pos: 0, eof: false }
    }

    fn fill(&mut self) -> Result<bool> {
        if self.eof {
            return Ok(false);
        }
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let old = self.buf.len();
        self.buf.resize(old + 64 * 1024, 0);
        let n = read(self.fd, &mut self.buf[old..])?;
        self.buf.truncate(old + n);
        if n == 0 {
            self.eof = true;
        }
        Ok(n > 0)
    }

    /// The next line including its newline (the last may lack one);
    /// `None` at end of input.
    pub fn line(&mut self) -> Result<Option<Vec<u8>>> {
        self.split(b'\n')
    }

    /// The next record ending in `delim` (inclusive).
    pub fn split(&mut self, delim: u8) -> Result<Option<Vec<u8>>> {
        Ok(self.split_ref(delim)?.map(<[u8]>::to_vec))
    }

    /// [`Reader::split`] without a copy: the record stays in the buffer
    /// until the next read.
    pub fn split_ref(&mut self, delim: u8) -> Result<Option<&[u8]>> {
        // Bytes already searched are not searched again after a refill.
        let mut scanned = 0;
        let end = loop {
            if let Some(i) = find_byte(delim, &self.buf[self.pos + scanned..]) {
                break self.pos + scanned + i + 1;
            }
            scanned = self.buf.len() - self.pos;
            if !self.fill()? {
                if self.pos < self.buf.len() {
                    break self.buf.len();
                }
                return Ok(None);
            }
        };
        let start = self.pos;
        self.pos = end;
        Ok(Some(&self.buf[start..end]))
    }

    /// Up to `max` bytes; empty at end of input.
    pub fn chunk(&mut self, max: usize) -> Result<Vec<u8>> {
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            if !self.fill()? {
                return Ok(Vec::new());
            }
        }
        let n = max.min(self.buf.len() - self.pos);
        let c = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(c)
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

/// `struct pollfd` (poll(2)).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

pub const POLLIN: i16 = 1;
pub const POLLOUT: i16 = 4;
pub const POLLERR: i16 = 8;
pub const POLLHUP: i16 = 0x10;

/// poll(2): EINTR is returned (a caught signal wakes the caller).
pub fn poll(fds: &mut [PollFd], timeout_ms: i32) -> Result<usize> {
    crate::syscall!(sys::pick(sys::POLL, nr::POLL), fds.as_mut_ptr(), fds.len(), timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::find_byte;

    #[test]
    fn byte_search() {
        let h: alloc::vec::Vec<u8> = (0..40u8).collect();
        for b in [0u8, 7, 8, 9, 15, 16, 31, 39] {
            assert_eq!(find_byte(b, &h), Some(b as usize));
        }
        assert_eq!(find_byte(99, &h), None);
        assert_eq!(find_byte(b'\n', b""), None);
        // Bytes with the high bit set beside the one sought.
        assert_eq!(find_byte(b'\n', &[0x8a, 0x80, 0xff, 0x0b, 0x09, b'\n', 0x8a, 0x0a]), Some(5));
    }
}
