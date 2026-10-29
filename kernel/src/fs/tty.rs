// SPDX-License-Identifier: MIT OR Apache-2.0

//! Terminals: the line discipline, the console terminal, and pseudo-
//! terminals (pty(7)).
//!
//! Behavior follows termios(3), ioctl_tty(2) and credentials(7) (sessions,
//! foreground process groups, background access): canonical mode (line
//! editing with ERASE/WERASE/KILL/EOF), echo, CR-to-NL input translation,
//! NL-to-CR-NL output translation, signal characters (INTR, QUIT, SUSP)
//! sent to the foreground process group, non-canonical reads with
//! VMIN/VTIME, and SIGTTIN/SIGTTOU for background jobs. The kernel `struct
//! termios` layout (36 bytes) and default settings were observed with
//! TCGETS on a Linux pty; flag values are from musl `bits/termios.h` and
//! ioctl numbers from musl `bits/ioctl.h` (ADR 0009).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use slate_sync::Once;

use super::vfs::{Metadata, Result, S_IFCHR, makedev};
use super::{File, O_NONBLOCK, O_RDWR, POLLHUP, POLLIN, POLLOUT, poll_notify};
use crate::abi::linux::errno::{EAGAIN, EFAULT, EINVAL, EIO, ENOTTY, EPERM};
use crate::abi::linux::ioctl::*;
use crate::arch::uaccess::{read_user, write_user};
use crate::proc::signal::{self, ERESTARTSYS, SIGHUP, SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGWINCH};
use crate::sched::wait::{WaitQueue, WaitResult};
use crate::sync::IrqSpinLock;

// c_iflag
const ICRNL: u32 = 0o400;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const IXON: u32 = 0o2000;
// c_oflag
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
// c_cflag
const B38400: u32 = 0o17;
/// The speed bits of c_cflag, and the speeds they name (musl
/// `bits/termios.h`; termios(3) "Line control").
const CBAUD: u32 = 0o10017;
/// The input speed: CBAUD's bits this far up (CIBAUD; 0 is "the output
/// speed").
const IBSHIFT: u32 = 16;
const B115200: u32 = 0o10002;
const SPEEDS: &[(u32, u32)] = &[
    (1, 50),
    (2, 75),
    (3, 110),
    (5, 150),
    (6, 200),
    (7, 300),
    (8, 600),
    (9, 1200),
    (10, 1800),
    (11, 2400),
    (12, 4800),
    (13, 9600),
    (14, 19200),
    (15, 38400),
    (0o10001, 57600),
    (B115200, 115_200),
];
const CS8: u32 = 0o60;
const CREAD: u32 = 0o200;
/// The rest of the line's settings (musl `bits/termios.h`; termios(3)
/// "Control modes"): character size, two stop bits, parity, odd parity,
/// hardware flow control.
const CSIZE: u32 = 0o60;
const CSTOPB: u32 = 0o100;
const PARENB: u32 = 0o400;
const PARODD: u32 = 0o1000;
const CRTSCTS: u32 = 0o20000000000;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const NOFLSH: u32 = 0o200;
const TOSTOP: u32 = 0o400;
const ECHOCTL: u32 = 0o1000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
// c_cc indices
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSUSP: usize = 10;
/// A control character set to this is disabled (termios(3), _POSIX_VDISABLE).
const VDISABLE: u8 = 0;
const VWERASE: usize = 14;

/// Device numbers (observed on Linux: /dev/ptmx is 5:2, slaves 136:N).
pub const PTMX_MAJOR: u32 = 5;
pub const PTMX_MINOR: u32 = 2;
pub const PTS_MAJOR: u32 = 136;
/// Most pseudo-terminals at once.
const MAX_PTYS: u32 = 256;
/// A pty's output held for its master: slave writers wait beyond it, as
/// on Linux (the size is ours), and echoes beyond it are dropped.
const PTY_OUTPUT_MAX: usize = 64 * 1024;
/// Input held for a terminal's reader: master writers wait beyond it, and
/// the console drops what arrives (the size is ours).
const INPUT_MAX: usize = 4096;

/// The kernel `struct termios` (TCGETS/TCSETS).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
}

const _: () = assert!(size_of::<Termios>() == 36);

impl Termios {
    /// Linux's defaults for a fresh terminal (observed: iflag 0x500, oflag 5,
    /// cflag 0xf00bf, the input speed too, lflag 0x8a3b and the control
    /// characters below; GNU stty -g on a pty).
    const DEFAULT: Termios = Termios {
        iflag: ICRNL | IXON,
        oflag: OPOST | ONLCR,
        cflag: B38400 | (B38400 << IBSHIFT) | CS8 | CREAD,
        lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
        line: 0,
        cc: [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0],
    };
}

#[derive(Debug)]
struct Input {
    /// The line being edited (canonical mode).
    line: Vec<u8>,
    /// Bytes ready for read(): completed lines, or raw input.
    ready: VecDeque<u8>,
    /// Complete lines (or EOFs) in `ready` (canonical mode).
    lines: usize,
    /// EOFs (^D on an empty line) waiting to be read as 0 bytes.
    eofs: usize,
}

impl Input {
    const fn new() -> Input {
        Input { line: Vec::new(), ready: VecDeque::new(), lines: 0, eofs: 0 }
    }

    fn flush(&mut self) {
        self.line.clear();
        self.ready.clear();
        self.lines = 0;
        self.eofs = 0;
    }
}

/// The master side of a pseudo-terminal, as seen by its slave.
#[derive(Debug)]
pub struct PtyLink {
    index: u32,
    /// Slave output, waiting for the master to read it.
    to_master: IrqSpinLock<VecDeque<u8>>,
    master_wq: WaitQueue,
    master_open: AtomicBool,
    slave_opens: AtomicUsize,
    /// Set once a slave has been opened: only then does "no slave open"
    /// mean hang-up (reads return EIO).
    slave_seen: AtomicBool,
    locked: AtomicBool,
    /// Owner and permissions of /dev/pts/N: (uid, gid, mode bits).
    attrs: IrqSpinLock<(u32, u32, u32)>,
}

impl PtyLink {
    fn slave_gone(&self) -> bool {
        self.slave_seen.load(Ordering::Acquire) && self.slave_opens.load(Ordering::Acquire) == 0
    }
}

#[derive(Debug)]
enum Kind {
    Console,
    Pty(PtyLink),
}

/// A terminal: line discipline state plus where its output goes.
#[derive(Debug)]
pub struct Tty {
    kind: Kind,
    termios: IrqSpinLock<Termios>,
    input: IrqSpinLock<Input>,
    winsize: IrqSpinLock<Winsize>,
    wq: WaitQueue,
    /// Foreground process group, and the session this is the controlling
    /// terminal of (0 = none).
    fg_pgrp: AtomicU32,
    session: AtomicU32,
    /// Input events, for edge-triggered epoll.
    events: core::sync::atomic::AtomicU64,
    /// When it was last read and written (seconds), in 8-second steps:
    /// stat's atime and mtime, from which who -u and w tell idle time,
    /// coarse so that they do not tell keystrokes apart.
    times: IrqSpinLock<(i64, i64)>,
}

static CONSOLE: Once<Arc<Tty>> = Once::new();
static PTYS: IrqSpinLock<BTreeMap<u32, Weak<Tty>>> = IrqSpinLock::new(BTreeMap::new());

fn new_tty(kind: Kind, winsize: Winsize) -> Tty {
    Tty {
        kind,
        termios: IrqSpinLock::new(Termios::DEFAULT),
        input: IrqSpinLock::new(Input::new()),
        winsize: IrqSpinLock::new(winsize),
        wq: WaitQueue::new(),
        fg_pgrp: AtomicU32::new(0),
        session: AtomicU32::new(0),
        events: core::sync::atomic::AtomicU64::new(1),
        times: IrqSpinLock::new((coarse_now(), coarse_now())),
    }
}

/// Now, rounded down to 8 seconds.
fn coarse_now() -> i64 {
    let s = super::vfs::Timespec::now().sec;
    s - s.rem_euclid(8)
}

/// The access and modification times of the terminal with device number
/// `rdev` (the console, or a pty's slave), if it is one.
pub fn times_of(rdev: u64) -> Option<(super::vfs::Timespec, super::vfs::Timespec)> {
    use super::devices::{CONSOLE_MINOR, TTY_MAJOR, TTYAUX_MAJOR, TTYS0_MINOR};
    let (major, minor) = (super::vfs::major(rdev), super::vfs::minor(rdev));
    let tty = match (major, minor) {
        (TTYAUX_MAJOR, CONSOLE_MINOR) | (TTY_MAJOR, TTYS0_MINOR) => console().clone(),
        (PTS_MAJOR, n) => PTYS.lock().get(&n)?.upgrade()?,
        _ => return None,
    };
    Some(tty.times())
}

/// The console terminal (serial port and screen).
pub fn console() -> &'static Arc<Tty> {
    CONSOLE.call_once(|| {
        let (rows, cols) = crate::console::size();
        let tty = new_tty(Kind::Console, Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 });
        // The serial line's real speed.
        let mut t = tty.termios.lock();
        t.cflag = (t.cflag & !(CBAUD | CBAUD << IBSHIFT)) | B115200 | B115200 << IBSHIFT;
        drop(t);
        Arc::new(tty)
    })
}

/// The console terminal if it exists yet (for interrupt handlers).
pub fn console_if_ready() -> Option<&'static Arc<Tty>> {
    CONSOLE.get()
}

impl Tty {
    /// Make `sid`/`pgid` the session and foreground group of this terminal.
    pub fn set_controlling(&self, sid: u32, pgid: u32) {
        self.session.store(sid, Ordering::Relaxed);
        self.fg_pgrp.store(pgid, Ordering::Relaxed);
    }

    pub fn foreground(&self) -> u32 {
        self.fg_pgrp.load(Ordering::Relaxed)
    }

    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Relaxed)
    }

    /// Device number (for stat and /proc).
    /// When it was last read and written.
    pub fn times(&self) -> (super::vfs::Timespec, super::vfs::Timespec) {
        let (a, m) = *self.times.lock();
        (super::vfs::Timespec { sec: a, nsec: 0 }, super::vfs::Timespec { sec: m, nsec: 0 })
    }

    fn touch(&self, write: bool) {
        let now = coarse_now();
        let mut t = self.times.lock();
        if write {
            t.1 = now;
        } else {
            t.0 = now;
        }
    }

    pub fn rdev(&self) -> u64 {
        match &self.kind {
            Kind::Console => makedev(super::devices::TTYAUX_MAJOR, super::devices::CONSOLE_MINOR),
            Kind::Pty(l) => makedev(PTS_MAJOR, l.index),
        }
    }

    /// The session leader is gone (or the master hung up): signal the
    /// foreground group and forget the session.
    pub fn hangup(&self) {
        let fg = self.fg_pgrp.swap(0, Ordering::Relaxed);
        self.session.store(0, Ordering::Relaxed);
        if fg != 0 {
            signal::send_to_group(fg, SIGHUP);
            signal::send_to_group(fg, signal::SIGCONT);
        }
        self.wq.wake_all();
        poll_notify();
    }

    /// Send output to wherever this terminal shows it.
    fn emit(&self, bytes: &[u8]) {
        match &self.kind {
            Kind::Console => crate::console::tty_output(bytes),
            Kind::Pty(l) => {
                if l.master_open.load(Ordering::Acquire) {
                    let mut q = l.to_master.lock();
                    if q.len() < PTY_OUTPUT_MAX {
                        q.extend(bytes);
                    }
                    drop(q);
                    l.master_wq.wake_all();
                    poll_notify();
                }
            }
        }
    }

    /// Output with OPOST processing (ONLCR: NL becomes CR NL).
    fn output(&self, buf: &[u8]) {
        let t = *self.termios.lock();
        if t.oflag & OPOST != 0 && t.oflag & ONLCR != 0 && buf.contains(&b'\n') {
            let mut v = Vec::with_capacity(buf.len() + 16);
            for &b in buf {
                if b == b'\n' {
                    v.push(b'\r');
                }
                v.push(b);
            }
            self.emit(&v);
        } else {
            self.emit(buf);
        }
    }

    /// Feed one received byte through the line discipline. For the console
    /// this runs in an interrupt handler.
    pub fn receive(&self, mut b: u8) {
        let t = *self.termios.lock();
        if b == b'\r' {
            if t.iflag & IGNCR != 0 {
                return;
            }
            if t.iflag & ICRNL != 0 {
                b = b'\n';
            }
        } else if b == b'\n' && t.iflag & INLCR != 0 {
            b = b'\r';
        }
        if t.lflag & ISIG != 0 {
            let is = |i: usize| t.cc[i] != VDISABLE && b == t.cc[i];
            let sig = if is(VINTR) {
                Some(SIGINT)
            } else if is(VQUIT) {
                Some(SIGQUIT)
            } else if is(VSUSP) {
                Some(SIGTSTP)
            } else {
                None
            };
            if let Some(sig) = sig {
                if t.lflag & ECHO != 0 {
                    self.output(&[b'^', b + 0x40, b'\n']);
                }
                if t.lflag & NOFLSH == 0 {
                    self.input.lock().flush();
                    self.input_taken();
                }
                let pg = self.fg_pgrp.load(Ordering::Relaxed);
                if pg != 0 {
                    if sig == SIGTSTP {
                        crate::log_info!("tty: suspend character {b:#04x}: SIGTSTP to process group {pg}");
                    }
                    signal::send_to_group(pg, sig);
                }
                return;
            }
        }
        // The mode decides where the byte goes: read it under the input
        // lock, which TCSETS also holds while it changes the mode (and moves
        // a partly typed line), so a byte arriving during the change cannot
        // be left in the line buffer of a terminal that is no longer
        // canonical.
        let mut i = self.input.lock();
        let t = *self.termios.lock();
        if t.lflag & ICANON != 0 {
            let out = Self::receive_canonical(&mut i, b, &t);
            drop(i);
            if !out.is_empty() {
                self.output(&out);
            }
        } else {
            if i.ready.len() >= INPUT_MAX {
                return;
            }
            i.ready.push_back(b);
            drop(i);
            if t.lflag & ECHO != 0 {
                self.echo_char(b, &t);
            }
        }
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wq.wake_all();
        poll_notify();
    }

    fn echo_char(&self, b: u8, t: &Termios) {
        if b < 0x20 && b != b'\n' && b != b'\t' && t.lflag & ECHOCTL != 0 {
            self.output(&[b'^', b + 0x40]);
        } else {
            self.output(&[b]);
        }
    }

    /// Canonical-mode editing of one byte; returns what to echo.
    fn receive_canonical(i: &mut Input, b: u8, t: &Termios) -> Vec<u8> {
        let echo_on = t.lflag & ECHO != 0;
        let mut erase = 0;
        let mut out: Vec<u8> = Vec::new();
        {
            if (t.cc[VERASE] != VDISABLE && b == t.cc[VERASE]) || b == 0x08 {
                if i.line.pop().is_some() {
                    erase = 1;
                }
            } else if t.cc[VWERASE] != VDISABLE && b == t.cc[VWERASE] && t.lflag & IEXTEN != 0 {
                while i.line.last() == Some(&b' ') {
                    i.line.pop();
                    erase += 1;
                }
                while i.line.last().is_some_and(|&c| c != b' ') {
                    i.line.pop();
                    erase += 1;
                }
            } else if t.cc[VKILL] != VDISABLE && b == t.cc[VKILL] {
                erase = i.line.len();
                i.line.clear();
                if t.lflag & ECHOK == 0 {
                    erase = 0;
                }
            } else if t.cc[VEOF] != VDISABLE && b == t.cc[VEOF] {
                let line = core::mem::take(&mut i.line);
                if line.is_empty() {
                    i.eofs += 1;
                }
                i.ready.extend(line);
                i.lines += 1;
            } else if b == b'\n' {
                let mut line = core::mem::take(&mut i.line);
                line.push(b'\n');
                i.ready.extend(line);
                i.lines += 1;
                if echo_on || t.lflag & ECHONL != 0 {
                    out.push(b'\n');
                }
            } else {
                if i.line.len() < 4095 {
                    i.line.push(b);
                }
                if echo_on {
                    if b < 0x20 && b != b'\t' && t.lflag & ECHOCTL != 0 {
                        out.extend([b'^', b + 0x40]);
                    } else {
                        out.push(b);
                    }
                }
            }
        }
        if echo_on && t.lflag & ECHOE != 0 {
            for _ in 0..erase {
                out.extend(b"\x08 \x08");
            }
        }
        out
    }

    /// Whether the input has room for another byte from the master.
    fn input_room(&self) -> bool {
        self.input.lock().ready.len() < INPUT_MAX
    }

    /// Whether `b` raises a signal (ISIG): such bytes take no room, so a
    /// full input never keeps ^C from the program.
    fn signal_char(&self, b: u8) -> bool {
        let t = *self.termios.lock();
        t.lflag & ISIG != 0 && [VINTR, VQUIT, VSUSP].iter().any(|&i| t.cc[i] != VDISABLE && t.cc[i] == b)
    }

    /// Input was read or flushed: wake master writers waiting for room.
    fn input_taken(&self) {
        if let Kind::Pty(l) = &self.kind {
            l.master_wq.wake_all();
            poll_notify();
        }
    }

    /// Whether read() would return data (or EOF) right now.
    fn has_input(&self) -> bool {
        let t = *self.termios.lock();
        let i = self.input.lock();
        if t.lflag & ICANON != 0 { i.lines > 0 } else { !i.ready.is_empty() }
    }

    fn hung_up(&self) -> bool {
        matches!(&self.kind, Kind::Pty(l) if !l.master_open.load(Ordering::Acquire))
    }

    /// Job control for the calling process (ioctl_tty(2), "Controlling
    /// terminal"; credentials(7)): a background process reading (or
    /// writing with TOSTOP, or changing settings) gets `sig` sent to its
    /// group and the call restarts once it is in the foreground.
    fn job_check(self: &Arc<Self>, sig: u32) -> Result<()> {
        let Some(p) = crate::proc::current() else { return Ok(()) };
        let is_ctty = p.ctty().is_some_and(|c| Arc::ptr_eq(&c, self));
        let pgid = p.pgid.load(Ordering::Relaxed);
        if !is_ctty || pgid == self.foreground() || self.foreground() == 0 {
            return Ok(());
        }
        let t = crate::sched::current();
        let blocked_or_ignored =
            t.signal_mask() & signal::bit(sig) != 0 || p.signals.action(sig).handler == signal::SIG_IGN;
        if blocked_or_ignored {
            // Reads fail; writes and settings changes are allowed.
            return if sig == SIGTTIN { Err(EIO) } else { Ok(()) };
        }
        if crate::proc::is_orphaned_pgrp(pgid) {
            return Err(EIO);
        }
        // Rare in practice and puzzling when it happens: say who and why.
        let name = p.name.lock().clone();
        crate::log_info!(
            "tty: pid {} ({name}) in background group {pgid} (foreground {}): {}",
            p.pid,
            self.foreground(),
            if sig == SIGTTIN { "read, SIGTTIN" } else { "write or settings, SIGTTOU" }
        );
        signal::send_to_group(pgid, sig);
        Err(ERESTARTSYS)
    }

    fn read(self: &Arc<Self>, buf: &mut [u8], nonblock: bool) -> Result<usize> {
        self.job_check(SIGTTIN)?;
        if buf.is_empty() {
            return Ok(0);
        }
        let t = *self.termios.lock();
        let canonical = t.lflag & ICANON != 0;
        let (vmin, vtime) = (t.cc[VMIN], t.cc[VTIME]);
        if !self.has_input() {
            if self.hung_up() {
                return Ok(0);
            }
            if nonblock {
                return Err(EAGAIN);
            }
            let ready = || self.has_input() || self.hung_up();
            let r = if !canonical && vmin == 0 && vtime > 0 {
                let deadline = crate::time::monotonic_ns() + u64::from(vtime) * 100_000_000;
                self.wq.wait_until_deadline(ready, deadline)
            } else if !canonical && vmin == 0 {
                WaitResult::Ready
            } else if self.wq.wait_until_interruptible(ready) {
                WaitResult::Interrupted
            } else {
                WaitResult::Ready
            };
            if r == WaitResult::Interrupted {
                return Err(ERESTARTSYS);
            }
        }
        let n = self.take_input(buf, canonical);
        if n > 0 {
            self.input_taken();
            self.touch(false);
        }
        Ok(n)
    }

    /// Read what is ready into `buf` (canonical: up to a line).
    fn take_input(&self, buf: &mut [u8], canonical: bool) -> usize {
        let mut i = self.input.lock();
        let mut n = 0;
        if canonical {
            if i.eofs > 0 && i.ready.is_empty() {
                i.eofs -= 1;
                i.lines -= 1;
                return 0;
            }
            while n < buf.len() {
                let Some(c) = i.ready.pop_front() else { break };
                buf[n] = c;
                n += 1;
                if c == b'\n' {
                    i.lines -= 1;
                    break;
                }
            }
            if i.ready.is_empty() && i.lines > 0 && n > 0 && buf[n - 1] != b'\n' {
                i.lines -= 1; // An EOF-terminated partial line was consumed.
            }
        } else {
            while n < buf.len() {
                let Some(c) = i.ready.pop_front() else { break };
                buf[n] = c;
                n += 1;
            }
        }
        n
    }

    /// Write to the terminal. A pty's output waits for room once its
    /// master has PTY_OUTPUT_MAX unread (or ends short, or EAGAIN, when
    /// non-blocking).
    fn write(self: &Arc<Self>, buf: &[u8], nonblock: bool) -> Result<usize> {
        if self.termios.lock().lflag & TOSTOP != 0 {
            self.job_check(SIGTTOU)?;
        }
        if self.hung_up() {
            return Err(EIO);
        }
        if !buf.is_empty() {
            self.touch(true);
        }
        let Kind::Pty(l) = &self.kind else {
            self.output(buf);
            return Ok(buf.len());
        };
        let mut done = 0;
        while done < buf.len() {
            let room = PTY_OUTPUT_MAX.saturating_sub(l.to_master.lock().len());
            if room == 0 {
                let stop = if nonblock {
                    Some(EAGAIN)
                } else if self
                    .wq
                    .wait_until_interruptible(|| l.to_master.lock().len() < PTY_OUTPUT_MAX || self.hung_up())
                {
                    Some(ERESTARTSYS)
                } else if self.hung_up() {
                    Some(EIO)
                } else {
                    None
                };
                match stop {
                    Some(_) if done > 0 => break,
                    Some(e) => return Err(e),
                    None => continue,
                }
            }
            let n = room.min(buf.len() - done);
            self.output(&buf[done..done + n]);
            done += n;
        }
        Ok(done)
    }

    fn ioctl(self: &Arc<Self>, cmd: u32, arg: u64) -> Result<u64> {
        let fault = |_| EFAULT;
        match cmd {
            TCGETS => {
                write_user(arg, &*self.termios.lock()).map_err(fault)?;
            }
            TCSETS | TCSETSW | TCSETSF => {
                self.job_check(SIGTTOU)?;
                let mut t: Termios = read_user(arg).map_err(fault)?;
                // The console's speed is the serial line's: a new one sets
                // the UART, and one it can't take (or B0) is left as it was.
                if matches!(self.kind, Kind::Console) {
                    let old = self.termios.lock().cflag & CBAUD;
                    let new = t.cflag & CBAUD;
                    let set = new == old
                        || SPEEDS
                            .iter()
                            .find(|(b, _)| *b == new)
                            .is_some_and(|&(_, baud)| crate::console::set_serial_speed(baud));
                    if !set {
                        t.cflag = (t.cflag & !CBAUD) | old;
                    }
                    // Its framing and flow control are the UART's too.
                    let f = crate::arch::serial::Framing {
                        bits: 5 + ((t.cflag & CSIZE) >> 4) as u8,
                        two_stop: t.cflag & CSTOPB != 0,
                        parity: (t.cflag & PARENB != 0).then_some(t.cflag & PARODD != 0),
                    };
                    crate::console::set_serial_line(f, t.cflag & CRTSCTS != 0);
                }
                // The input lock first: `receive` reads the mode under it.
                let mut i = self.input.lock();
                let old = core::mem::replace(&mut *self.termios.lock(), t);
                if cmd == TCSETSF {
                    i.flush();
                    self.input_taken();
                }
                // Leaving canonical mode: a partly typed line becomes plain
                // input instead of being lost.
                if old.lflag & ICANON != 0 && t.lflag & ICANON == 0 {
                    let line = core::mem::take(&mut i.line);
                    i.ready.extend(line);
                    i.lines = 0;
                    i.eofs = 0;
                }
                // Switching to canonical mode: count the complete lines.
                if t.lflag & ICANON != 0 {
                    i.lines = i.ready.iter().filter(|&&c| c == b'\n').count();
                }
                drop(i);
                self.wq.wake_all();
            }
            TIOCGWINSZ => {
                write_user(arg, &*self.winsize.lock()).map_err(fault)?;
            }
            TIOCSWINSZ => {
                let ws: Winsize = read_user(arg).map_err(fault)?;
                *self.winsize.lock() = ws;
                let fg = self.foreground();
                if fg != 0 {
                    signal::send_to_group(fg, SIGWINCH);
                }
            }
            TIOCGPGRP => {
                write_user(arg, &crate::proc::pid_out(self.fg_pgrp.load(Ordering::Relaxed))).map_err(fault)?;
            }
            TIOCSPGRP => {
                self.job_check(SIGTTOU)?;
                let pg: u32 = read_user(arg).map_err(fault)?;
                let p = crate::proc::current().ok_or(ENOTTY)?;
                if !p.ctty().is_some_and(|c| Arc::ptr_eq(&c, self)) {
                    return Err(ENOTTY);
                }
                self.fg_pgrp.store(crate::proc::pgid_in(pg), Ordering::Relaxed);
            }
            TIOCGSID => {
                let s = self.session.load(Ordering::Relaxed);
                if s == 0 {
                    return Err(ENOTTY);
                }
                write_user(arg, &crate::proc::pid_out(s)).map_err(fault)?;
            }
            TIOCSCTTY => {
                let p = crate::proc::current().ok_or(EPERM)?;
                let sid = p.sid.load(Ordering::Relaxed);
                // Already ours (opening it made it so): nothing to do, as
                // on Linux (observed).
                if sid == p.pid && p.ctty().is_some_and(|c| Arc::ptr_eq(&c, self)) {
                    return Ok(0);
                }
                if sid != p.pid || p.ctty().is_some() {
                    return Err(EPERM); // Only a session leader without one.
                }
                let owner = self.session();
                // Owned by another session: arg 1 steals it, with
                // CAP_SYS_ADMIN (ioctl_tty(2)).
                if owner != 0 && owner != sid && (arg != 1 || !p.cred().capable(crate::proc::cred::CAP_SYS_ADMIN)) {
                    return Err(EPERM);
                }
                self.set_controlling(sid, p.pgid.load(Ordering::Relaxed));
                p.set_ctty(Some(self.clone()));
            }
            TIOCNOTTY => {
                let p = crate::proc::current().ok_or(ENOTTY)?;
                if !p.ctty().is_some_and(|c| Arc::ptr_eq(&c, self)) {
                    return Err(ENOTTY);
                }
                p.set_ctty(None);
                if p.sid.load(Ordering::Relaxed) == p.pid {
                    self.hangup();
                }
            }
            FIONREAD => {
                let n = self.input.lock().ready.len() as u32;
                write_user(arg, &n).map_err(fault)?;
            }
            _ => return Err(EINVAL),
        }
        Ok(0)
    }
}

/// An open file on a terminal (the console or a pty slave).
#[derive(Debug)]
pub struct TtyFile {
    tty: Arc<Tty>,
    flags: AtomicU32,
}

impl TtyFile {
    fn new(tty: Arc<Tty>, flags: u32) -> TtyFile {
        if let Kind::Pty(l) = &tty.kind {
            l.slave_opens.fetch_add(1, Ordering::AcqRel);
            l.slave_seen.store(true, Ordering::Release);
        }
        TtyFile { tty, flags: AtomicU32::new(flags) }
    }
}

/// Open the console terminal.
pub fn open_console() -> Arc<dyn File> {
    Arc::new(TtyFile::new(console().clone(), O_RDWR))
}

/// Open a terminal; a session leader without a controlling terminal
/// acquires it unless `O_NOCTTY` is given (open(2)).
pub fn open_tty(tty: Arc<Tty>, flags: u32) -> Arc<dyn File> {
    if flags & super::O_NOCTTY == 0
        && let Some(p) = crate::proc::current()
        && p.sid.load(Ordering::Relaxed) == p.pid
        && p.ctty().is_none()
        && tty.session() == 0
    {
        tty.set_controlling(p.pid, p.pgid.load(Ordering::Relaxed));
        p.set_ctty(Some(tty.clone()));
    }
    Arc::new(TtyFile::new(tty, flags))
}

impl File for TtyFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.tty.read(buf, self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.tty.write(buf, self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        self.tty.ioctl(cmd, arg)
    }

    fn stat(&self) -> Result<Metadata> {
        let (atime, mtime) = self.tty.times();
        Ok(Metadata { mode: S_IFCHR | 0o620, nlink: 1, rdev: self.tty.rdev(), atime, mtime, ..Default::default() })
    }

    fn poll(&self) -> u16 {
        let mut r = match &self.tty.kind {
            Kind::Pty(l) if l.to_master.lock().len() >= PTY_OUTPUT_MAX => 0,
            _ => POLLOUT,
        };
        if self.tty.has_input() {
            r |= POLLIN;
        }
        if self.tty.hung_up() {
            r |= POLLHUP | POLLIN;
        }
        r
    }

    fn event_count(&self) -> u64 {
        self.tty.events.load(Ordering::Relaxed)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !super::SETFL_MASK) | (flags & super::SETFL_MASK), Ordering::Relaxed);
    }
}

impl Drop for TtyFile {
    fn drop(&mut self) {
        if let Kind::Pty(l) = &self.tty.kind {
            l.slave_opens.fetch_sub(1, Ordering::AcqRel);
            l.master_wq.wake_all();
            poll_notify();
        }
    }
}

// --- Pseudo-terminals -----------------------------------------------------

/// The master side of a pseudo-terminal (/dev/ptmx).
#[derive(Debug)]
pub struct PtyMaster {
    tty: Arc<Tty>,
    flags: AtomicU32,
}

impl PtyMaster {
    fn link(&self) -> &PtyLink {
        match &self.tty.kind {
            Kind::Pty(l) => l,
            Kind::Console => unreachable!("console has no master"),
        }
    }
}

/// Allocate a new pseudo-terminal; returns its master file.
pub fn open_master(flags: u32) -> Result<Arc<dyn File>> {
    let mut ptys = PTYS.lock();
    ptys.retain(|_, t| t.strong_count() > 0);
    let index = (0..MAX_PTYS).find(|i| !ptys.contains_key(i)).ok_or(crate::abi::linux::errno::ENOSPC)?;
    let link = PtyLink {
        index,
        to_master: IrqSpinLock::new(VecDeque::new()),
        master_wq: WaitQueue::new(),
        master_open: AtomicBool::new(true),
        slave_opens: AtomicUsize::new(0),
        slave_seen: AtomicBool::new(false),
        locked: AtomicBool::new(true),
        // pts(4): the slave starts out owned by the opener of /dev/ptmx;
        // grantpt(3) then adjusts it with chown and chmod.
        attrs: IrqSpinLock::new(crate::proc::current().map_or((0, 0, 0o620), |p| {
            let c = p.cred();
            (c.fsuid, c.fsgid, 0o620)
        })),
    };
    let tty = Arc::new(new_tty(Kind::Pty(link), Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 }));
    ptys.insert(index, Arc::downgrade(&tty));
    Ok(Arc::new(PtyMaster { tty, flags: AtomicU32::new(flags) }))
}

fn pty_link<R>(index: u32, f: impl FnOnce(&PtyLink) -> R) -> Option<R> {
    let tty = PTYS.lock().get(&index).and_then(Weak::upgrade)?;
    match &tty.kind {
        Kind::Pty(l) => Some(f(l)),
        Kind::Console => None,
    }
}

/// Owner and mode of /dev/pts/`index`: (uid, gid, permission bits).
pub fn pty_attrs(index: u32) -> Option<(u32, u32, u32)> {
    pty_link(index, |l| *l.attrs.lock())
}

/// Change the owner or mode of /dev/pts/`index`.
pub fn set_pty_attrs(index: u32, uid: Option<u32>, gid: Option<u32>, mode: Option<u32>) -> Option<()> {
    pty_link(index, |l| {
        let mut a = l.attrs.lock();
        a.0 = uid.unwrap_or(a.0);
        a.1 = gid.unwrap_or(a.1);
        a.2 = mode.map_or(a.2, |m| m & 0o7777);
    })
}

/// Open the slave of pty `index` (/dev/pts/N).
pub fn open_slave(index: u32, flags: u32) -> Result<Arc<dyn File>> {
    let tty = PTYS.lock().get(&index).and_then(Weak::upgrade).ok_or(crate::abi::linux::errno::ENXIO)?;
    match &tty.kind {
        Kind::Pty(l) if l.locked.load(Ordering::Acquire) || !l.master_open.load(Ordering::Acquire) => Err(EIO),
        _ => Ok(open_tty(tty, flags)),
    }
}

/// Indices of the pseudo-terminals in use (for /dev/pts).
pub fn pty_indices() -> Vec<u32> {
    PTYS.lock().iter().filter(|(_, t)| t.upgrade().is_some_and(|t| !t.hung_up())).map(|(&i, _)| i).collect()
}

impl File for PtyMaster {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let l = self.link();
        loop {
            {
                let mut q = l.to_master.lock();
                if !q.is_empty() {
                    let n = buf.len().min(q.len());
                    for (d, s) in buf.iter_mut().zip(q.drain(..n)) {
                        *d = s;
                    }
                    drop(q);
                    // Slave writers waiting for room.
                    self.tty.wq.wake_all();
                    poll_notify();
                    return Ok(n);
                }
            }
            // Once a slave was opened and every slave is closed again,
            // reads fail like Linux's (EIO).
            if l.slave_gone() {
                return Err(EIO);
            }
            if self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            let ready = || !l.to_master.lock().is_empty() || l.slave_gone();
            if l.master_wq.wait_until_interruptible(ready) {
                return Err(ERESTARTSYS);
            }
        }
    }

    /// Input for the slave: waits while its reader has INPUT_MAX unread
    /// (or ends short, or EAGAIN, when non-blocking); EIO once every slave
    /// is closed.
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let l = self.link();
        let nonblock = self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0;
        let mut done = 0;
        while done < buf.len() {
            if !self.tty.input_room() && !self.tty.signal_char(buf[done]) {
                let stop = if l.slave_gone() {
                    Some(EIO)
                } else if nonblock {
                    Some(EAGAIN)
                } else if l.master_wq.wait_until_interruptible(|| self.tty.input_room() || l.slave_gone()) {
                    Some(ERESTARTSYS)
                } else {
                    None
                };
                match stop {
                    Some(_) if done > 0 => break,
                    Some(e) => return Err(e),
                    None => continue,
                }
            }
            self.tty.receive(buf[done]);
            done += 1;
        }
        Ok(done)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        let l = self.link();
        match cmd {
            TIOCGPTN => {
                write_user(arg, &l.index).map_err(|_| EFAULT)?;
                Ok(0)
            }
            TIOCSPTLCK => {
                let lock: i32 = read_user(arg).map_err(|_| EFAULT)?;
                l.locked.store(lock != 0, Ordering::Release);
                Ok(0)
            }
            TIOCGPTLCK => {
                write_user(arg, &i32::from(l.locked.load(Ordering::Acquire))).map_err(|_| EFAULT)?;
                Ok(0)
            }
            // The foreground process group of the terminal's slave side, as
            // terminal emulators ask with tcgetpgrp() on the master
            // (ioctl_tty(2), TIOCGPGRP).
            TIOCGPGRP => {
                write_user(arg, &(self.tty.foreground() as i32)).map_err(|_| EFAULT)?;
                Ok(0)
            }
            TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ | FIONREAD => {
                // Settings of the pty, as seen from the master side.
                if cmd == FIONREAD {
                    write_user(arg, &(l.to_master.lock().len() as u32)).map_err(|_| EFAULT)?;
                    return Ok(0);
                }
                self.tty.ioctl(cmd, arg)
            }
            _ => Err(EINVAL),
        }
    }

    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFCHR | 0o666, nlink: 1, rdev: makedev(PTMX_MAJOR, PTMX_MINOR), ..Default::default() })
    }

    fn poll(&self) -> u16 {
        let l = self.link();
        let mut r = if self.tty.input_room() { POLLOUT } else { 0 };
        if !l.to_master.lock().is_empty() {
            r |= POLLIN;
        }
        if l.slave_gone() {
            r |= POLLHUP;
        }
        r
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !super::SETFL_MASK) | (flags & super::SETFL_MASK), Ordering::Relaxed);
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        let l = self.link();
        l.master_open.store(false, Ordering::Release);
        self.tty.hangup();
        PTYS.lock().remove(&l.index);
    }
}

// Keep the unused-flag lint quiet for documented flags not yet acted on.
const _: u32 = IXON;
