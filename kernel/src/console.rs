// SPDX-License-Identifier: MIT OR Apache-2.0

//! Kernel console output.
//!
//! Everything printed goes to the first serial port. A framebuffer console
//! joins it in milestone M7.

use core::fmt::{self, Write};

use crate::arch::serial::SerialPort;
use crate::sync::IrqSpinLock;

static SERIAL: IrqSpinLock<SerialPort> = IrqSpinLock::new(SerialPort::COM1);

/// Initialize the console devices.
pub fn init() {
    SERIAL.lock().init();
}

/// Start interrupt-driven console input (needs the interrupt controllers).
/// Set the serial console's line speed (termios(3)'s speeds the UART's
/// clock divides into); false if it can't.
pub fn set_serial_speed(baud: u32) -> bool {
    SERIAL.lock().set_speed(baud)
}

/// Set the serial console's framing and hardware flow control.
pub fn set_serial_line(f: crate::arch::serial::Framing, rtscts: bool) {
    SERIAL.lock().set_line(f, rtscts);
}

pub fn init_input() {
    crate::arch::irq::register_isa(crate::arch::serial::COM1_IRQ, "serial", serial_interrupt);
    SERIAL.lock().enable_rx_interrupt();
}

fn serial_interrupt() {
    let mut bytes = [0u8; 64];
    loop {
        let mut n = 0;
        {
            let mut serial = SERIAL.lock();
            while n < bytes.len()
                && let Some(b) = serial.try_read_byte()
            {
                bytes[n] = b;
                n += 1;
            }
        }
        if n == 0 {
            return;
        }
        if let Some(tty) = crate::fs::tty::console_if_ready() {
            for &b in &bytes[..n] {
                tty.receive(b);
            }
        }
    }
}

#[doc(hidden)]
pub fn print(args: fmt::Arguments<'_>) {
    // Formatting into a serial port cannot fail.
    let _ = SERIAL.lock().write_fmt(args);
    screen_print(args, false);
}

/// Print from the panic handler, even if the console lock is held: the
/// panicking code may have held it, and it will never release it.
pub fn panic_print(args: fmt::Arguments<'_>) {
    if SERIAL.is_locked() {
        // SAFETY: The panicking CPU may hold the lock and will never release
        // it. If another CPU holds it, output may interleave, which is
        // acceptable for a dying kernel.
        unsafe { SERIAL.force_unlock() };
    }
    let _ = SERIAL.lock().write_fmt(args);
    screen_print(args, true);
}

/// Print to the kernel console.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::console::print(format_args!($($arg)*)));
}

/// Print a line to the kernel console.
#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::console::print(format_args!("{}\n", format_args!($($arg)*))));
}

/// Write bytes to the console without newline translation.
pub fn write_raw(bytes: &[u8]) {
    let mut s = SERIAL.lock();
    for &b in bytes {
        s.write_byte(b);
    }
}

/// Output of the console terminal (already processed by its line
/// discipline): to the serial port and the screen. Replies the screen's
/// terminal gives (cursor position reports) are fed back as input.
pub fn tty_output(bytes: &[u8]) {
    write_raw(bytes);
    let replies = crate::drivers::fbcon::write(bytes);
    if !replies.is_empty()
        && let Some(tty) = crate::fs::tty::console_if_ready()
    {
        for b in replies {
            tty.receive(b);
        }
    }
}

/// Size of the console in (rows, columns): the screen's, if there is one.
pub fn size() -> (u16, u16) {
    crate::drivers::fbcon::size().unwrap_or((24, 80))
}

/// Streams kernel text to the screen through a small stack buffer (no heap
/// use, so it also works while panicking); newlines become CR LF.
struct ScreenWriter {
    buf: [u8; 256],
    len: usize,
    panicking: bool,
}

impl ScreenWriter {
    fn flush(&mut self) {
        if self.len > 0 {
            if self.panicking {
                crate::drivers::fbcon::try_show(&self.buf[..self.len]);
            } else {
                crate::drivers::fbcon::show(&self.buf[..self.len]);
            }
            self.len = 0;
        }
    }
}

impl Write for ScreenWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if self.len + 2 > self.buf.len() {
                self.flush();
            }
            if b == b'\n' {
                self.buf[self.len] = b'\r';
                self.len += 1;
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

fn screen_print(args: fmt::Arguments<'_>, panicking: bool) {
    let mut w = ScreenWriter { buf: [0; 256], len: 0, panicking };
    let _ = w.write_fmt(args);
    w.flush();
}
