// SPDX-License-Identifier: MIT OR Apache-2.0

//! I/O port access (Intel SDM vol. 2, IN/OUT).

use core::arch::asm;

/// An 8-bit I/O port.
#[derive(Clone, Copy, Debug)]
pub struct Port8(u16);

impl Port8 {
    /// # Safety
    ///
    /// Reads and writes to `port` must not break memory safety: the port must
    /// not be one that, for example, reprograms DMA into arbitrary memory.
    pub const unsafe fn new(port: u16) -> Port8 {
        Port8(port)
    }

    pub fn read(self) -> u8 {
        let v: u8;
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("in al, dx", out("al") v, in("dx") self.0, options(nomem, nostack, preserves_flags)) };
        v
    }

    pub fn write(self, v: u8) {
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("out dx, al", in("dx") self.0, in("al") v, options(nomem, nostack, preserves_flags)) };
    }
}

/// A 16-bit I/O port.
#[derive(Clone, Copy, Debug)]
pub struct Port16(u16);

impl Port16 {
    /// # Safety
    ///
    /// As for [`Port8::new`].
    pub const unsafe fn new(port: u16) -> Port16 {
        Port16(port)
    }

    pub fn read(self) -> u16 {
        let v: u16;
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("in ax, dx", out("ax") v, in("dx") self.0, options(nomem, nostack, preserves_flags)) };
        v
    }

    pub fn write(self, v: u16) {
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("out dx, ax", in("dx") self.0, in("ax") v, options(nomem, nostack, preserves_flags)) };
    }

    /// Read `buf.len() / 2` words into `buf` with one `rep insw` (Intel SDM
    /// vol. 2, INS; a hypervisor moves the whole run in few exits).
    pub fn read_words(self, buf: &mut [u8]) {
        // SAFETY: The constructor's contract covers the port; RDI and RCX
        // describe `buf`, which INS writes word by word upwards (DF is
        // clear in Rust code, as the System V ABI requires).
        unsafe {
            asm!(
                "rep insw",
                in("dx") self.0,
                inout("rdi") buf.as_mut_ptr() => _,
                inout("rcx") buf.len() / 2 => _,
                options(nostack, preserves_flags)
            )
        };
    }

    /// Write `buf.len() / 2` words from `buf` with one `rep outsw`.
    pub fn write_words(self, buf: &[u8]) {
        // SAFETY: As in `read_words`; OUTS only reads `buf`.
        unsafe {
            asm!(
                "rep outsw",
                in("dx") self.0,
                inout("rsi") buf.as_ptr() => _,
                inout("rcx") buf.len() / 2 => _,
                options(nostack, preserves_flags, readonly)
            )
        };
    }
}

/// A 32-bit I/O port.
#[derive(Clone, Copy, Debug)]
pub struct Port32(u16);

impl Port32 {
    /// # Safety
    ///
    /// As for [`Port8::new`].
    pub const unsafe fn new(port: u16) -> Port32 {
        Port32(port)
    }

    pub fn read(self) -> u32 {
        let v: u32;
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("in eax, dx", out("eax") v, in("dx") self.0, options(nomem, nostack, preserves_flags)) };
        v
    }

    pub fn write(self, v: u32) {
        // SAFETY: The constructor's contract makes accesses to this port safe.
        unsafe { asm!("out dx, eax", in("dx") self.0, in("eax") v, options(nomem, nostack, preserves_flags)) };
    }
}
