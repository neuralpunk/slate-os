// SPDX-License-Identifier: MIT OR Apache-2.0

//! 16550-compatible UART driver for the PC serial ports.
//!
//! Register layout from the National Semiconductor PC16550D datasheet
//! (offsets from the port base, DLAB = divisor latch access bit in LCR).

use core::fmt;

use super::port::Port8;

const DATA: u16 = 0; // RBR/THR, or DLL when DLAB = 1
const IER: u16 = 1; // interrupt enable, or DLM when DLAB = 1
const FCR: u16 = 2; // FIFO control (write)
const LCR: u16 = 3; // line control
const MCR: u16 = 4; // modem control
const LSR: u16 = 5; // line status
const MSR: u16 = 6; // modem status

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const FCR_ENABLE_CLEAR_14: u8 = 0xC7; // enable FIFOs, clear both, 14-byte trigger
const MCR_DTR_RTS_OUT2: u8 = 0x0B;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_DATA_READY: u8 = 0x01;
const IER_RX_AVAILABLE: u8 = 0x01;
/// MSR: the other end is ready for data (Clear To Send).
const MSR_CTS: u8 = 0x10;
/// How long a byte waits for CTS before it goes anyway (spins of the
/// status read, about a second): a cable without the line must not hang
/// the console.
const CTS_SPINS: u32 = 1_000_000;

/// ISA IRQ of COM1.
pub const COM1_IRQ: u8 = 4;

/// Base clock 115200 Hz divided by this gives the baud rate.
const DIVISOR_115200: u16 = 1;

/// A serial port at a fixed I/O base.
#[derive(Debug)]
pub struct SerialPort {
    base: u16,
    present: bool,
    /// Wait for CTS before each byte (termios' CRTSCTS).
    rtscts: bool,
}

/// A line's framing: data bits (5 to 8), two stop bits, parity (`None`,
/// or odd).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framing {
    pub bits: u8,
    pub two_stop: bool,
    pub parity: Option<bool>,
}

impl Framing {
    /// The LCR bits (PC16550D datasheet, "Line Control Register"): word
    /// length in bits 0 and 1, two stop bits in bit 2, parity enable in
    /// bit 3, even parity in bit 4.
    pub fn lcr(self) -> u8 {
        let mut v = self.bits.clamp(5, 8) - 5;
        if self.two_stop {
            v |= 0x04;
        }
        if let Some(odd) = self.parity {
            v |= 0x08;
            if !odd {
                v |= 0x10;
            }
        }
        v
    }
}

impl SerialPort {
    /// The first PC serial port.
    pub const COM1: SerialPort = SerialPort { base: 0x3F8, present: false, rtscts: false };

    fn reg(&self, offset: u16) -> Port8 {
        // SAFETY: The UART registers only affect the UART; `base` is one of the
        // standard PC serial port bases.
        unsafe { Port8::new(self.base + offset) }
    }

    /// Program 115200 baud, 8N1, FIFOs on, interrupts off. Detects whether a
    /// UART is present with a scratch-free loopback check; writes to an absent
    /// port are dropped.
    pub fn init(&mut self) {
        self.reg(IER).write(0x00);
        self.reg(LCR).write(LCR_DLAB);
        self.reg(DATA).write(DIVISOR_115200 as u8);
        self.reg(IER).write((DIVISOR_115200 >> 8) as u8);
        self.reg(LCR).write(LCR_8N1);
        self.reg(FCR).write(FCR_ENABLE_CLEAR_14);

        // Loopback self-test (MCR bit 4): a byte sent comes straight back.
        self.reg(MCR).write(0x1E);
        self.reg(DATA).write(0xAE);
        self.present = self.reg(DATA).read() == 0xAE;
        self.reg(MCR).write(MCR_DTR_RTS_OUT2);
    }

    /// Set the line speed to `baud` (the base clock divided by a whole
    /// number: 115200, 57600, 38400, ... 50). False for other speeds.
    pub fn set_speed(&mut self, baud: u32) -> bool {
        if baud == 0 || 115_200 % baud != 0 || 115_200 / baud > u32::from(u16::MAX) {
            return false;
        }
        let d = (115_200 / baud) as u16;
        if self.present {
            // Let what is queued leave at the old speed first.
            while self.reg(LSR).read() & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            let lcr = self.reg(LCR).read();
            self.reg(LCR).write(lcr | LCR_DLAB);
            self.reg(DATA).write(d as u8);
            self.reg(IER).write((d >> 8) as u8);
            self.reg(LCR).write(lcr & !LCR_DLAB);
        }
        true
    }

    /// Set the line's framing and flow control; what is queued leaves
    /// with the old framing first.
    pub fn set_line(&mut self, f: Framing, rtscts: bool) {
        self.rtscts = rtscts;
        if !self.present {
            return;
        }
        while self.reg(LSR).read() & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        let dlab = self.reg(LCR).read() & LCR_DLAB;
        self.reg(LCR).write(f.lcr() | dlab);
    }

    /// Interrupt when a byte arrives.
    pub fn enable_rx_interrupt(&mut self) {
        if self.present {
            self.reg(IER).write(IER_RX_AVAILABLE);
        }
    }

    /// A received byte, if one is waiting.
    pub fn try_read_byte(&mut self) -> Option<u8> {
        (self.present && self.reg(LSR).read() & LSR_DATA_READY != 0).then(|| self.reg(DATA).read())
    }

    pub fn write_byte(&mut self, b: u8) {
        if !self.present {
            return;
        }
        while self.reg(LSR).read() & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        if self.rtscts {
            let mut n = 0;
            while self.reg(MSR).read() & MSR_CTS == 0 && n < CTS_SPINS {
                core::hint::spin_loop();
                n += 1;
            }
        }
        self.reg(DATA).write(b);
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}
