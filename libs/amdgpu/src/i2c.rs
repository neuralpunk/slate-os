// SPDX-License-Identifier: MIT OR Apache-2.0

//! The display engine's I2C engine on a DDC line (ADR 0171, M32 phase 4,
//! step 7): the monitor's EDID, and HDMI's SCDC registers, read the way DC
//! reads them (no bit-banging).
//!
//! Facts from DC (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code):
//!
//! - The engine (dce_i2c_hw.c, `setup_engine`, `acquire_engine`,
//!   `process_transaction`, `execute_transaction`, `get_channel_status`,
//!   `process_channel_reply`, `release_engine`; dce_i2c_hw.h): software
//!   asks for it in `DC_I2C_ARBITRATION` (its status, bits 3:2, says 1
//!   when software has it); `DC_I2C_CONTROL` picks the DDC line (10:8),
//!   the number of transactions less one (21:20) and starts them (GO);
//!   up to four transactions (`DC_I2C_TRANSACTIONn`: read, stop on NACK,
//!   start, stop, a byte count in 25:16) share a 144-byte buffer
//!   (`DC_I2C_DATA`: the byte in 15:8, an index in 25:16 set with bit
//!   31, bit 0 to read). Each transaction's first byte is the address
//!   (shifted, bit 0 for a read); a write's bytes follow it.
//!   `DC_I2C_SW_STATUS`: busy while 1:0 is 1, done (bit 2), aborted (4),
//!   timed out (5), stopped on a NACK (8).
//! - The line's speed (`set_speed`): a prescale of the reference clock
//!   (`MICROSECOND_TIME_BASE_DIV`'s base divider in MHz, over its crystal
//!   divider) over the speed in kHz, threshold 2, start/stop timing 2
//!   above 50 kHz; DCN 3.1.5 runs it at 100 kHz (dcn315_resource.c). On
//!   the reference PC, amdgpu left 0078_0202h (prescale 120: 24 MHz / 2 / 100 kHz),
//!   and `DC_I2C_DDC1_SETUP` 0300_0040h (a time limit of 3, enabled).
//! - The pad (gpio/hw_ddc.c, `set_config`, I2C mode): the line's pull-
//!   downs on (`DC_GPIO_DDCn_MASK` bits 4 and 12), out of AUX mode (bit
//!   16), `DC_GPIO_AUX_CTRL_5`'s `DDC_PADn_I2CMODE` on (bit 11 + n), and
//!   the pad's receiver select (`PHY_AUX_CNTL`'s `AUXn_PAD_RXSEL`, two bits
//!   from bit 8 + 2n) at 1 ("set DC_IO_aux_rxsel = 2'b01"); amdgpu left
//!   0015_5400h, every pad at 1.
//! - The engine's buffer is a memory kept in light sleep between
//!   transfers (`DIO_MEM_PWR_CTRL`'s `I2C_LIGHT_SLEEP_FORCE`, amdgpu
//!   leaves it 1): DC wakes it and waits for `DIO_MEM_PWR_STATUS`'s
//!   `I2C_MEM_PWR_STATE` to clear before a transfer, and puts it back to
//!   sleep after (`setup_engine`, `release_engine`, with
//!   `enable_mem_low_power.bits.i2c`, which dcn315_resource.c sets).
//!   Asleep, the engine sends what it can't read: the address goes
//!   unanswered.
//! - The registers: dcn_3_1_5_offset.h and dcn_3_1_5_sh_mask.h (DCN's
//!   segment 2), below.
//! - The DDC line is the VBIOS's i2c_id's line (bits 3:0): HDMI's 90h is
//!   line 0, DDC1 (DC maps it through the GPIO pin table, bios_parser2.c;
//!   on the reference PC the two agree).
//! - EDID over DDC (VESA E-DDC 1.3): the EDID at I2C address 50h, an
//!   offset written first; blocks past the second through the segment
//!   pointer at 30h. HDMI's SCDC (HDMI 2.0 §10.4) is at 54h.

use alloc::vec::Vec;

use crate::interp::Card;

/// Segment 2 register words (dcn_3_1_5_offset.h).
pub mod reg {
    pub const MICROSECOND_TIME_BASE_DIV_SEG1: u32 = 0x7B;
    pub const CONTROL: u32 = 0x1E98;
    pub const ARBITRATION: u32 = 0x1E99;
    pub const SW_STATUS: u32 = 0x1E9B;
    /// `DC_I2C_DDCn_HW_STATUS` is `HW_STATUS + n`, `_SPEED` `SPEED + 2n`,
    /// `_SETUP` one after it.
    pub const HW_STATUS: u32 = 0x1E9C;
    pub const SPEED: u32 = 0x1EA2;
    pub const TRANSACTION0: u32 = 0x1EAE;
    pub const DATA: u32 = 0x1EB2;
    /// `DC_GPIO_DDCn_MASK` is `GPIO_DDC_MASK + 4n`.
    pub const GPIO_DDC_MASK: u32 = 0x28D0;
    pub const GPIO_AUX_CTRL_5: u32 = 0x291D;
    pub const PHY_AUX_CNTL: u32 = 0x28FF;
    pub const DIO_MEM_PWR_STATUS: u32 = 0x1EDD;
    pub const DIO_MEM_PWR_CTRL: u32 = 0x1EDE;
}

const GO: u32 = 1;
const SOFT_RESET: u32 = 1 << 1;
const SEND_RESET: u32 = 1 << 2;
const SW_STATUS_RESET: u32 = 1 << 3;
const DDC_SELECT_SHIFT: u32 = 8;
const TRANSACTION_COUNT_SHIFT: u32 = 20;

const RW_CNTL_STATUS_SHIFT: u32 = 2;
const RW_CNTL_STATUS: u32 = 3 << RW_CNTL_STATUS_SHIFT;
const NO_QUEUED_SW_GO: u32 = 1 << 4;
const SW_USE_I2C_REG_REQ: u32 = 1 << 20;
const SW_DONE_USING_I2C_REG: u32 = 1 << 21;
const USED_BY_SW: u32 = 1;
const USED_BY_HW: u32 = 2;

const SW_BUSY: u32 = 3;
const SW_DONE: u32 = 1 << 2;
const SW_ABORTED: u32 = 1 << 4;
const SW_TIMEOUT: u32 = 1 << 5;
const SW_STOPPED_ON_NACK: u32 = 1 << 8;

const SETUP_ENABLE: u32 = 1 << 6;
const SETUP_DRIVES: u32 = 0x0000_0083 | 0x00FF_FF00;
const TIME_LIMIT_DCN: u32 = 3 << 24;

const T_RW: u32 = 1;
const T_STOP_ON_NACK: u32 = 1 << 8;
const T_START: u32 = 1 << 12;
const T_STOP: u32 = 1 << 13;
const T_COUNT_SHIFT: u32 = 16;

const D_RW: u32 = 1;
const D_INDEX_SHIFT: u32 = 16;
const D_INDEX_WRITE: u32 = 1 << 31;

const PD_EN: u32 = (1 << 4) | (1 << 12);
const AUX_PAD_MODE: u32 = 1 << 16;
const I2CMODE_SHIFT: u32 = 12;
const RXSEL_SHIFT: u32 = 10;
const I2C_LIGHT_SLEEP_FORCE: u32 = 1;
const I2C_MEM_PWR_STATE: u32 = 1;

/// The engine's buffer, and the largest read that fits with its offset.
const BUFFER: usize = 144;
pub const MAX_READ: usize = 128;
const SPEED_KHZ: u32 = 100;

pub const EDID: u8 = 0x50;
pub const SEGMENT: u8 = 0x30;
pub const SCDC: u8 = 0x54;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No such line, or a transfer too big for the engine.
    Invalid,
    /// The hardware (or DMCUB) has the engine.
    Busy,
    /// Nothing answered (`DC_I2C_SW_STATUS`: bits 15:12 say which
    /// transactions were refused).
    Nack(u32),
    Timeout,
    Aborted,
}

/// One part of a transfer.
#[derive(Debug)]
pub enum Op<'a> {
    Write(u8, &'a [u8]),
    Read(u8, &'a mut [u8]),
}

/// A DDC line (0 is DDC1) on DCN 3.1's I2C engine.
#[derive(Clone, Copy, Debug)]
pub struct Ddc {
    seg1: u32,
    seg2: u32,
    line: u32,
}

impl Ddc {
    /// DCN's segment 1 and 2 bases, and the line (the VBIOS's i2c_id's
    /// bits 3:0).
    pub fn new(seg1: u32, seg2: u32, line: u8) -> Option<Self> {
        (line < 5).then_some(Ddc { seg1, seg2, line: u32::from(line) })
    }

    fn rd(&self, card: &mut impl Card, r: u32) -> u32 {
        card.read(self.seg2 + r)
    }
    fn wr(&self, card: &mut impl Card, r: u32, v: u32) {
        card.write(self.seg2 + r, v)
    }
    fn update(&self, card: &mut impl Card, r: u32, clear: u32, set: u32) {
        let v = self.rd(card, r);
        self.wr(card, r, (v & !clear) | set)
    }

    fn acquire(&self, card: &mut impl Card) -> Result<(), Error> {
        // The pad in I2C mode.
        let mask = reg::GPIO_DDC_MASK + 4 * self.line;
        self.update(card, mask, AUX_PAD_MODE, PD_EN);
        self.update(card, reg::GPIO_AUX_CTRL_5, 0, 1 << (I2CMODE_SHIFT + self.line));
        let rxsel = RXSEL_SHIFT + 2 * self.line;
        self.update(card, reg::PHY_AUX_CNTL, 3 << rxsel, 1 << rxsel);
        self.update(card, reg::CONTROL, SOFT_RESET, 0);
        // Its buffer awake.
        self.update(card, reg::DIO_MEM_PWR_CTRL, I2C_LIGHT_SLEEP_FORCE, 0);
        for _ in 0..100 {
            if self.rd(card, reg::DIO_MEM_PWR_STATUS) & I2C_MEM_PWR_STATE == 0 {
                break;
            }
            card.delay_us(1);
        }
        let status = |s: &Self, c: &mut _| (s.rd(c, reg::ARBITRATION) & RW_CNTL_STATUS) >> RW_CNTL_STATUS_SHIFT;
        match status(self, card) {
            USED_BY_SW => {}
            USED_BY_HW => return Err(Error::Busy),
            _ => {
                self.update(card, reg::ARBITRATION, 0, SW_USE_I2C_REG_REQ);
                if status(self, card) != USED_BY_SW {
                    return Err(Error::Busy);
                }
            }
        }
        // 100 kHz.
        let tb = card.read(self.seg1 + reg::MICROSECOND_TIME_BASE_DIV_SEG1);
        let (base, xtal) = (tb & 0x7F, ((tb >> 8) & 0x7F).max(1));
        let prescale = (base * 1000 / xtal) / SPEED_KHZ;
        let speed = reg::SPEED + 2 * self.line;
        self.wr(card, speed, (prescale << 16) | (2 << 8) | 2);
        let control =
            self.rd(card, reg::CONTROL) & !(GO | SEND_RESET | (3 << TRANSACTION_COUNT_SHIFT) | (7 << DDC_SELECT_SHIFT));
        self.wr(card, reg::CONTROL, control | SW_STATUS_RESET | (self.line << DDC_SELECT_SHIFT));
        self.wr(card, speed + 1, TIME_LIMIT_DCN | SETUP_ENABLE);
        self.update(card, reg::ARBITRATION, NO_QUEUED_SW_GO, 0);
        Ok(())
    }

    fn release(&self, card: &mut impl Card) {
        let sw = self.rd(card, reg::SW_STATUS) & SW_BUSY;
        let reset = if sw == USED_BY_SW { SOFT_RESET | SW_STATUS_RESET } else { SW_STATUS_RESET };
        self.update(card, reg::CONTROL, 0, reset);
        self.update(card, reg::ARBITRATION, 0, SW_DONE_USING_I2C_REG);
        self.update(card, reg::DIO_MEM_PWR_CTRL, 0, I2C_LIGHT_SLEEP_FORCE);
    }

    /// Run up to four transactions as one (a repeated start between them,
    /// a stop after the last).
    pub fn transfer(&self, card: &mut impl Card, ops: &mut [Op]) -> Result<(), Error> {
        let used: usize = ops
            .iter()
            .map(|o| match o {
                Op::Write(_, d) => 1 + d.len(),
                Op::Read(_, d) => 1 + d.len(),
            })
            .sum();
        if ops.is_empty() || ops.len() > 4 || used > BUFFER {
            return Err(Error::Invalid);
        }
        self.acquire(card)?;
        let r = self.run(card, ops);
        self.release(card);
        r
    }

    fn run(&self, card: &mut impl Card, ops: &mut [Op]) -> Result<(), Error> {
        let last = ops.len() - 1;
        for (i, op) in ops.iter().enumerate() {
            let (addr, read, len, data): (u8, bool, usize, &[u8]) = match op {
                Op::Write(a, d) => (*a, false, d.len(), d),
                Op::Read(a, d) => (*a, true, d.len(), &[]),
            };
            let stop = if i == last { T_STOP } else { 0 };
            let rw = if read { T_RW } else { 0 };
            let t = T_STOP_ON_NACK | T_START | rw | ((len as u32) << T_COUNT_SHIFT) | stop;
            self.wr(card, reg::TRANSACTION0 + i as u32, t);
            let first = if i == 0 { D_INDEX_WRITE } else { 0 };
            let byte = (u32::from(addr) << 1) | u32::from(read);
            self.wr(card, reg::DATA, first | (byte << 8));
            for b in data {
                self.wr(card, reg::DATA, u32::from(*b) << 8);
            }
        }
        let setup = reg::SPEED + 2 * self.line + 1;
        self.update(card, setup, SETUP_DRIVES, 0);
        self.update(card, reg::CONTROL, 0, SW_STATUS_RESET);
        let control = self.rd(card, reg::CONTROL)
            & !(SOFT_RESET | SW_STATUS_RESET | SEND_RESET | GO | (3 << TRANSACTION_COUNT_SHIFT));
        self.wr(card, reg::CONTROL, control | ((last as u32) << TRANSACTION_COUNT_SHIFT));
        self.wr(card, reg::CONTROL, control | ((last as u32) << TRANSACTION_COUNT_SHIFT) | GO);
        // A 144-byte buffer at 100 kHz is about 13 ms; allow 50.
        let mut status = 0;
        for _ in 0..5000 {
            status = self.rd(card, reg::SW_STATUS);
            if status & SW_BUSY != USED_BY_SW {
                break;
            }
            card.delay_us(10);
        }
        if status & SW_BUSY == USED_BY_SW {
            return Err(Error::Timeout);
        }
        if status & SW_STOPPED_ON_NACK != 0 {
            return Err(Error::Nack(status));
        }
        if status & SW_TIMEOUT != 0 {
            return Err(Error::Timeout);
        }
        if status & SW_ABORTED != 0 {
            return Err(Error::Aborted);
        }
        if status & SW_DONE == 0 {
            return Err(Error::Timeout);
        }
        // The read bytes follow everything written before them.
        let mut index = 0;
        for op in ops.iter_mut() {
            match op {
                Op::Write(_, d) => index += 1 + d.len(),
                Op::Read(_, d) => {
                    index += 1;
                    self.wr(card, reg::DATA, D_INDEX_WRITE | ((index as u32) << D_INDEX_SHIFT) | D_RW);
                    for b in d.iter_mut() {
                        *b = (self.rd(card, reg::DATA) >> 8) as u8;
                    }
                    index += d.len();
                }
            }
        }
        Ok(())
    }

    /// `out.len()` bytes (at most 128) from register `offset` of `addr`.
    pub fn read(&self, card: &mut impl Card, addr: u8, offset: u8, out: &mut [u8]) -> Result<(), Error> {
        if out.len() > MAX_READ {
            return Err(Error::Invalid);
        }
        self.transfer(card, &mut [Op::Write(addr, &[offset]), Op::Read(addr, out)])
    }

    /// The monitor's EDID: the base block and its extensions (up to 7).
    pub fn edid(&self, card: &mut impl Card) -> Result<Vec<u8>, Error> {
        let mut block = [0u8; 128];
        self.read(card, EDID, 0, &mut block)?;
        let mut edid = block.to_vec();
        for n in 1..=usize::from(block[126]).min(7) {
            let offset = ((n % 2) * 128) as u8;
            if n < 2 {
                self.read(card, EDID, offset, &mut block)?;
            } else {
                let segment = [(n / 2) as u8];
                self.transfer(
                    card,
                    &mut [Op::Write(SEGMENT, &segment), Op::Write(EDID, &[offset]), Op::Read(EDID, &mut block)],
                )?;
            }
            edid.extend_from_slice(&block);
        }
        Ok(edid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;

    const SEG1: u32 = 0xC0;
    const SEG2: u32 = 0x34C0;

    /// The engine and, on its line, an EDID (two segments) and an SCDC.
    struct Engine {
        r: BTreeMap<u32, u32>,
        buffer: Vec<u8>,
        write_at: usize,
        read_at: usize,
        edid: Vec<u8>,
        segment: usize,
        offset: usize,
        line: u32,
        runs: u32,
    }

    impl Engine {
        fn new(line: u32, edid: Vec<u8>) -> Self {
            let mut r = BTreeMap::new();
            r.insert(SEG1 + reg::MICROSECOND_TIME_BASE_DIV_SEG1, 0x0012_0218);
            Engine { r, buffer: vec![0; BUFFER], write_at: 0, read_at: 0, edid, segment: 0, offset: 0, line, runs: 0 }
        }
        fn get(&self, r: u32) -> u32 {
            self.r.get(&(SEG2 + r)).copied().unwrap_or(0)
        }
        /// Run the transactions in the buffer (from a memory that reads all
        /// ones while it sleeps).
        fn go(&mut self) {
            self.runs += 1;
            if self.get(reg::DIO_MEM_PWR_CTRL) & I2C_LIGHT_SLEEP_FORCE != 0 {
                self.buffer.fill(0xFF);
            }
            let control = self.get(reg::CONTROL);
            let count = ((control >> TRANSACTION_COUNT_SHIFT) & 3) + 1;
            let mut at = 0;
            let mut status = SW_DONE;
            if (control >> DDC_SELECT_SHIFT) & 7 != self.line {
                status |= SW_STOPPED_ON_NACK;
            }
            for i in 0..count {
                let t = self.get(reg::TRANSACTION0 + i);
                assert_ne!(t & T_START, 0);
                assert_eq!(t & T_STOP != 0, i == count - 1, "a stop only after the last");
                let len = ((t >> T_COUNT_SHIFT) & 0x3FF) as usize;
                let byte = self.buffer[at];
                at += 1;
                let (addr, read) = (byte >> 1, byte & 1 == 1);
                assert_eq!(read, t & T_RW != 0);
                match (addr, read) {
                    (SEGMENT, false) => self.segment = usize::from(self.buffer[at]),
                    (EDID, false) => self.offset = usize::from(self.buffer[at]),
                    (EDID, true) => {
                        for k in 0..len {
                            let pos = self.segment * 256 + (self.offset + k) % 256;
                            self.buffer[at + k] = self.edid.get(pos).copied().unwrap_or(0xFF);
                        }
                        self.offset += len;
                    }
                    _ => status |= SW_STOPPED_ON_NACK,
                }
                at += len;
            }
            // A segment pointer lasts one transfer.
            self.segment = 0;
            self.r.insert(SEG2 + reg::SW_STATUS, status);
        }
    }

    impl Card for Engine {
        fn read(&mut self, reg: u32) -> u32 {
            if reg == SEG2 + reg::DIO_MEM_PWR_STATUS {
                return self.get(reg::DIO_MEM_PWR_CTRL) & I2C_LIGHT_SLEEP_FORCE;
            }
            if reg == SEG2 + reg::DATA {
                let b = self.buffer[self.read_at];
                self.read_at += 1;
                return u32::from(b) << 8;
            }
            self.r.get(&reg).copied().unwrap_or(0)
        }
        fn write(&mut self, reg: u32, v: u32) {
            match reg - SEG2 {
                reg::DATA => {
                    if v & D_INDEX_WRITE != 0 {
                        let i = ((v >> D_INDEX_SHIFT) & 0x3FF) as usize;
                        if v & D_RW != 0 {
                            self.read_at = i;
                            return;
                        }
                        self.write_at = i;
                    }
                    self.buffer[self.write_at] = (v >> 8) as u8;
                    self.write_at += 1;
                }
                reg::ARBITRATION => {
                    let mut v = v & !RW_CNTL_STATUS;
                    if v & SW_DONE_USING_I2C_REG != 0 {
                        v &= !(SW_USE_I2C_REG_REQ | SW_DONE_USING_I2C_REG);
                    }
                    if v & SW_USE_I2C_REG_REQ != 0 {
                        v |= USED_BY_SW << RW_CNTL_STATUS_SHIFT;
                    }
                    self.r.insert(reg, v);
                }
                reg::CONTROL => {
                    self.r.insert(reg, v & !GO);
                    if v & GO != 0 {
                        self.go();
                    }
                }
                _ => {
                    self.r.insert(reg, v);
                }
            }
        }
        fn delay_us(&mut self, _: u32) {}
    }

    fn edid(blocks: usize) -> Vec<u8> {
        let mut e: Vec<u8> = (0..128 * blocks).map(|i| (i * 7 + i / 128) as u8).collect();
        e[126] = (blocks - 1) as u8;
        e
    }

    #[test]
    fn reads_an_edid() {
        for blocks in [1, 2, 4] {
            let mut e = Engine::new(0, edid(blocks));
            let ddc = Ddc::new(SEG1, SEG2, 0).unwrap();
            assert_eq!(ddc.edid(&mut e).unwrap(), edid(blocks), "{blocks} blocks");
            assert_eq!(e.runs as usize, blocks);
            // The pad in I2C mode, 100 kHz from the time base, and the
            // engine given back.
            assert_eq!(e.get(reg::GPIO_DDC_MASK) & (PD_EN | AUX_PAD_MODE), PD_EN);
            assert_ne!(e.get(reg::GPIO_AUX_CTRL_5) & (1 << 12), 0);
            assert_eq!(e.get(reg::PHY_AUX_CNTL), 0x400);
            assert_eq!(e.get(reg::DIO_MEM_PWR_CTRL), I2C_LIGHT_SLEEP_FORCE);
            assert_eq!(e.get(reg::SPEED), 0x0078_0202);
            assert_eq!(e.get(reg::SPEED + 1) & !SETUP_DRIVES, 0x0300_0040);
            assert_eq!(e.get(reg::ARBITRATION) & RW_CNTL_STATUS, 0);
        }
        // Line 2 (DP-1's DDC): its own registers.
        let mut e = Engine::new(2, edid(1));
        let ddc = Ddc::new(SEG1, SEG2, 2).unwrap();
        assert_eq!(ddc.edid(&mut e).unwrap(), edid(1));
        assert_eq!(e.get(reg::SPEED + 4), 0x0078_0202);
        assert_ne!(e.get(reg::GPIO_AUX_CTRL_5) & (1 << 14), 0);
    }

    #[test]
    fn says_what_went_wrong() {
        // Nothing on the line; a buffer left asleep (as the engine would
        // be without waking it).
        let ddc = Ddc::new(SEG1, SEG2, 0).unwrap();
        let mut e = Engine::new(0, edid(1));
        e.r.insert(SEG2 + reg::DIO_MEM_PWR_CTRL, I2C_LIGHT_SLEEP_FORCE);
        assert!(ddc.edid(&mut e).is_ok());
        let mut e = Engine::new(1, edid(1));
        assert!(matches!(ddc.edid(&mut e), Err(Error::Nack(_))));
        // No device at that address.
        let mut e = Engine::new(0, edid(1));
        let mut b = [0u8; 2];
        assert!(matches!(ddc.read(&mut e, SCDC, 0x40, &mut b), Err(Error::Nack(_))));
        // Too much for the engine; no such line.
        assert_eq!(ddc.read(&mut e, EDID, 0, &mut [0u8; 129]), Err(Error::Invalid));
        assert!(Ddc::new(SEG1, SEG2, 5).is_none());
        // The hardware holds the engine.
        let mut e = Engine::new(0, edid(1));
        e.r.insert(SEG2 + reg::ARBITRATION, USED_BY_HW << RW_CNTL_STATUS_SHIFT);
        assert_eq!(ddc.edid(&mut e), Err(Error::Busy));
    }

    #[test]
    fn refpc_monitor() {
        // The monitor on the reference PC's outputs (its DisplayPort EDID, read under
        // Fedora), as a sink on the line.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/dp4.edid");
        let Ok(d) = std::fs::read(path) else { return };
        let mut e = Engine::new(0, d.clone());
        assert_eq!(Ddc::new(SEG1, SEG2, 0).unwrap().edid(&mut e).unwrap(), d);
    }
}
