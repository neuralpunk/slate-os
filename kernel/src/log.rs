// SPDX-License-Identifier: MIT OR Apache-2.0

//! Leveled kernel logging to the console.
//!
//! Lines look like `[    0.012345] warn  acpi: ignoring ACPI table ...`.
//! The threshold comes from `loglevel=<error|warn|info|debug|trace>` on the
//! kernel command line (default `info`). Timestamps are seconds since the
//! clock started (0 before that).

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn ",
            Level::Info => "info ",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => return None,
        })
    }
}

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_max_level(l: Level) {
    MAX_LEVEL.store(l as u8, Ordering::Relaxed);
}

/// Messages up to this level also go to the console (all enabled ones
/// reach the ring buffer).
static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(Level::Trace as u8);

/// Apply `loglevel=` from the kernel command line, if present, and
/// `quiet` (as on Linux: only warnings and errors on the console; the
/// ring buffer, and so `dmesg`, still has everything).
pub fn configure(cmdline: &str) {
    for word in cmdline.split_ascii_whitespace() {
        if word == "quiet" {
            CONSOLE_LEVEL.store(Level::Warn as u8, Ordering::Relaxed);
        }
        if let Some(v) = word.strip_prefix("loglevel=") {
            match Level::parse(v) {
                Some(l) => set_max_level(l),
                None => crate::log_warn!("ignoring unknown loglevel {v:?}"),
            }
        }
    }
}

pub fn enabled(l: Level) -> bool {
    l as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

#[doc(hidden)]
pub fn log(l: Level, module: &str, args: fmt::Arguments<'_>) {
    // Something went wrong: the boot splash shows the console (ADR 0186).
    if l == Level::Error {
        crate::drivers::fbcon::splash_error();
    }
    if enabled(l) {
        let module = match module {
            "slate_kernel" => "kernel",
            m => m.strip_prefix("slate_kernel::").unwrap_or(m),
        };
        let ns = crate::time::monotonic_ns();
        let (secs, micros) = (ns / 1_000_000_000, ns / 1000 % 1_000_000);
        let line = format_args!("[{secs:5}.{micros:06}] {} {module}: {args}\n", l.label());
        // Format before taking the ring's lock: arguments may take locks of
        // their own.
        let mut text = LineBuf { buf: [0; 1024], len: 0 };
        let _ = fmt::Write::write_fmt(&mut text, line);
        RING.lock().push(&text.buf[..text.len]);
        if l as u8 <= CONSOLE_LEVEL.load(Ordering::Relaxed) {
            crate::console::print(line);
        }
    }
}

/// The kernel log's last 256 KiB, for `syslog(2)` and `dmesg` (ADR 0029).
pub const RING_SIZE: usize = 256 * 1024;

pub struct Ring {
    buf: [u8; RING_SIZE],
    /// Total bytes ever written; the ring holds the last `RING_SIZE`.
    written: usize,
    /// `written` when the ring was last cleared.
    cleared: usize,
}

static RING: crate::sync::IrqSpinLock<Ring> =
    crate::sync::IrqSpinLock::new(Ring { buf: [0; RING_SIZE], written: 0, cleared: 0 });

impl Ring {
    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.written % RING_SIZE] = b;
            self.written += 1;
        }
    }
}

/// One log line, cut at 1 KiB (the console still gets all of it).
struct LineBuf {
    buf: [u8; 1024],
    len: usize,
}

impl fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// The log since it was last cleared (at most `RING_SIZE` bytes, starting
/// at a line boundary when older text was overwritten).
pub fn contents() -> alloc::vec::Vec<u8> {
    let r = RING.lock();
    let start = r.cleared.max(r.written.saturating_sub(RING_SIZE));
    let mut out: alloc::vec::Vec<u8> = (start..r.written).map(|i| r.buf[i % RING_SIZE]).collect();
    if start > 0
        && start != r.cleared
        && let Some(nl) = out.iter().position(|&b| b == b'\n')
    {
        out.drain(..=nl);
    }
    out
}

/// Whole lines written since `pos` (a count of bytes ever written; when
/// that text is gone, from the oldest line kept), at most `max` bytes,
/// and the position after them (ADR 0060).
pub fn read_from(pos: usize, max: usize) -> (alloc::vec::Vec<u8>, usize) {
    let r = RING.lock();
    let oldest = r.written.saturating_sub(RING_SIZE);
    let mut start = pos.min(r.written);
    let mut out = alloc::vec::Vec::new();
    if start < oldest {
        // Skip to the first line that is whole.
        start = oldest;
        while start < r.written && r.buf[start % RING_SIZE] != b'\n' {
            start += 1;
        }
        start = (start + 1).min(r.written);
    }
    let end = r.written.min(start + max);
    let mut last_nl = None;
    for i in start..end {
        let b = r.buf[i % RING_SIZE];
        out.push(b);
        if b == b'\n' {
            last_nl = Some(out.len());
        }
    }
    let keep = last_nl.unwrap_or(0);
    out.truncate(keep);
    (out, start + keep)
}

/// Bytes `contents` would return.
pub fn unread() -> usize {
    let r = RING.lock();
    r.written - r.cleared.max(r.written.saturating_sub(RING_SIZE))
}

pub fn clear() {
    let mut r = RING.lock();
    r.cleared = r.written;
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $($arg:tt)*) => ($crate::log::log($level, module_path!(), format_args!($($arg)*)));
}
#[macro_export]
macro_rules! log_error { ($($arg:tt)*) => ($crate::log_at!($crate::log::Level::Error, $($arg)*)); }
#[macro_export]
macro_rules! log_warn { ($($arg:tt)*) => ($crate::log_at!($crate::log::Level::Warn, $($arg)*)); }
#[macro_export]
macro_rules! log_info { ($($arg:tt)*) => ($crate::log_at!($crate::log::Level::Info, $($arg)*)); }
#[macro_export]
macro_rules! log_debug { ($($arg:tt)*) => ($crate::log_at!($crate::log::Level::Debug, $($arg)*)); }
#[macro_export]
macro_rules! log_trace { ($($arg:tt)*) => ($crate::log_at!($crate::log::Level::Trace, $($arg)*)); }

/// Settings already reported as accepted without effect: (program, what).
static IGNORED: crate::sync::IrqSpinLock<alloc::vec::Vec<(alloc::string::String, &'static str)>> =
    crate::sync::IrqSpinLock::new(alloc::vec::Vec::new());

/// A setting the kernel accepts and does not act on (a GAP, ADR 0077):
/// logged once per program, so a program that depends on one leaves a
/// trace.
pub fn accepted_without_effect(what: &'static str) {
    let (pid, comm) =
        crate::proc::current().map_or((0, alloc::string::String::new()), |p| (p.pid, p.name.lock().clone()));
    let mut seen = IGNORED.lock();
    if seen.iter().any(|(c, w)| *c == comm && *w == what) {
        return;
    }
    if seen.len() < 512 {
        seen.push((comm.clone(), what));
    }
    drop(seen);
    crate::log_warn!("pid {pid} ({comm}): {what}: accepted without effect");
}
