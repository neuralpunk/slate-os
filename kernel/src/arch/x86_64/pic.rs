// SPDX-License-Identifier: MIT OR Apache-2.0

//! The legacy 8259A PIC pair, which we only remap and mask (Intel 8259A
//! datasheet, initialization command words ICW1-ICW4).

use super::port::Port8;

/// Remap both PICs above the exception vectors (so a spurious IRQ 7 or 15
/// cannot look like an exception) and mask every line. The I/O APIC
/// delivers device interrupts instead.
pub fn disable() {
    // SAFETY: 0x20/0x21 and 0xA0/0xA1 are the PIC command/data ports; the
    // initialization sequence only affects the PICs.
    let (cmd1, data1, cmd2, data2) =
        unsafe { (Port8::new(0x20), Port8::new(0x21), Port8::new(0xA0), Port8::new(0xA1)) };
    cmd1.write(0x11); // ICW1: initialize, ICW4 follows
    cmd2.write(0x11);
    data1.write(0x20); // ICW2: vector base
    data2.write(0x28);
    data1.write(0x04); // ICW3: slave on IRQ2
    data2.write(0x02);
    data1.write(0x01); // ICW4: 8086 mode
    data2.write(0x01);
    data1.write(0xFF); // OCW1: mask everything
    data2.write(0xFF);
}
