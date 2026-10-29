// SPDX-License-Identifier: MIT OR Apache-2.0

//! AMD's security processor, the PSP (MP0; ADR 0171's second addendum):
//! on Raphael it alone may load DMCUB's code. Its trusted OS is already
//! running on an APU (the platform firmware starts it); the driver gives
//! it a command ring in the GPU's memory and sends it commands: the TOC
//! (which says how big a trusted memory region its firmware needs), the
//! trusted memory region (TMR) itself, then each firmware to load
//! (`LOAD_IP_FW`, AMD's signed image as the file has it).
//!
//! Facts from amdgpu (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code):
//!
//! - The mailbox (mp_13_0_5_offset.h, MP0's segment 0): `C2PMSG_64` the
//!   command and its answer (bit 31 "response", 15:0 the status),
//!   `C2PMSG_67` the ring's write pointer (in dwords), `C2PMSG_69`/`_70`
//!   the ring's address, `C2PMSG_71` its size, `C2PMSG_81` non-zero once
//!   the trusted OS runs (psp_v13_0.c: `psp_v13_0_ring_create`,
//!   `_ring_stop`, `_ring_get_wptr`, `_ring_set_wptr`, `_is_sos_alive`).
//!   Ring commands (psp_gfx_if.h): the kernel-mode ring's type 2 in bits
//!   23:16 makes it, 3_0000h destroys the rings; amdgpu waits 20 ms after
//!   writing one, then for the response bit.
//! - The ring (amdgpu_psp.c, `psp_ring_init`, `psp_ring_cmd_submit`):
//!   4 KiB of 64-byte frames (psp_gfx_if.h, `psp_gfx_rb_frame`: the
//!   command buffer's address at 0 and 4, the fence's at 12 and 16, the
//!   fence value at 20); the write pointer moves a frame (16 dwords) at a
//!   time, wrapping at the ring's size; the PSP writes the fence value
//!   when the command is done.
//! - A command (psp_gfx_if.h, `psp_gfx_cmd_resp`, in a 4 KiB buffer): the
//!   command ID at 8, its arguments from 28, the response at 864 (status,
//!   then the loaded firmware's address in the TMR at 8 and 12, the TMR
//!   size the TOC asks for at 16). IDs: `SETUP_TMR` 5, `LOAD_IP_FW` 6,
//!   `LOAD_TOC` 20h; firmware types: `GFX_FW_TYPE_DMUB` 51.
//!   `SETUP_TMR`'s arguments: the TMR's GPU address, its size, flags (bit
//!   1, `virt_phy_addr`: its system address follows), the system address
//!   (amdgpu_psp.c, `psp_prep_tmr_cmd_buf`); `LOAD_IP_FW`'s: the image's
//!   address, size and type; `LOAD_TOC`'s: the TOC's address and size.
//! - The TOC file (amdgpu_ucode.h, `psp_firmware_header_v1_0`): the
//!   common header's payload size at 14h and offset at 18h.
//! - What amdgpu did on the reference PC (its log): a 10 MiB TMR (A0_0000h) at GPU
//!   F4_1E00_0000h, DMCUB "loaded via PSP".

use crate::interp::Card;

/// MP0 segment 0 register words (mp_13_0_5_offset.h).
pub mod reg {
    pub const C2PMSG_35: u32 = 0x63;
    pub const C2PMSG_64: u32 = 0x80;
    pub const C2PMSG_67: u32 = 0x83;
    pub const C2PMSG_69: u32 = 0x85;
    pub const C2PMSG_70: u32 = 0x86;
    pub const C2PMSG_71: u32 = 0x87;
    pub const C2PMSG_81: u32 = 0x91;
}

const RESPONSE: u32 = 1 << 31;
const STATUS: u32 = 0xFFFF;
const INIT_KM_RING: u32 = 2 << 16;
const DESTROY_RINGS: u32 = 3 << 16;

pub const RING_SIZE: u32 = 0x1000;
const FRAME: u32 = 64;
/// The command buffer (and the fence's) size.
pub const BUFFER: usize = 0x1000;
const RESPONSE_AT: usize = 864;

pub const SETUP_TMR: u32 = 5;
pub const LOAD_IP_FW: u32 = 6;
pub const LOAD_TOC: u32 = 0x20;
pub const FW_DMUB: u32 = 51;
const TMR_SYSTEM_ADDRESS: u32 = 1 << 1;

/// The GPU's memory, at GPU addresses, as the driver reaches it.
pub trait Memory {
    fn put(&mut self, gpu: u64, data: &[u8]);
    fn get32(&mut self, gpu: u64) -> u32;
    /// Make what was written visible to the GPU (an HDP flush).
    fn flush(&mut self);
}

/// Where the driver's buffers for the PSP are (GPU addresses, 4 KiB
/// aligned): the ring, the command buffer, the fence, and a buffer for
/// the images it is given (`image_size` bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffers {
    pub ring: u64,
    pub command: u64,
    pub fence: u64,
    pub image: u64,
    pub image_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The trusted OS isn't running (C2PMSG_81 is 0).
    NotRunning,
    /// It didn't say it was ready for a ring (C2PMSG_64 as it was).
    NotReady(u32),
    /// It refused the ring (C2PMSG_64's answer).
    Ring(u32),
    /// A command didn't finish (its ID).
    Timeout(u32),
    /// A command failed (its ID, the response's status).
    Status(u32, u32),
    /// An image larger than the buffer for it.
    TooBig,
}

/// A command's response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u32,
    /// Where a loaded firmware went (in the TMR).
    pub fw_addr: u64,
    /// The TMR size the TOC asks for.
    pub tmr_size: u32,
}

/// The TOC's payload in its file.
pub fn toc(bin: &[u8]) -> Option<&[u8]> {
    let word = |at: usize| Some(u32::from_le_bytes(bin.get(at..at + 4)?.try_into().ok()?) as usize);
    let (size, at) = (word(0x14)?, word(0x18)?);
    bin.get(at..at.checked_add(size)?)
}

#[derive(Debug)]
pub struct Psp {
    /// MP0's segment 0 base (register words).
    mp0: u32,
    b: Buffers,
    fence: u32,
}

impl Psp {
    pub fn new(mp0: u32, b: Buffers) -> Self {
        Psp { mp0, b, fence: 0 }
    }

    fn read(&self, card: &mut impl Card, r: u32) -> u32 {
        card.read(self.mp0 + r)
    }

    /// Wait up to `ms` for C2PMSG_64's response bit; its value.
    fn answer(&self, card: &mut impl Card, ms: u32) -> Option<u32> {
        for _ in 0..ms * 10 {
            let v = self.read(card, reg::C2PMSG_64);
            if v & RESPONSE != 0 {
                return Some(v);
            }
            card.delay_us(100);
        }
        None
    }

    /// Give the trusted OS a kernel-mode ring.
    pub fn create_ring(&mut self, dev: &mut (impl Card + Memory)) -> Result<(), Error> {
        if self.read(dev, reg::C2PMSG_81) == 0 {
            return Err(Error::NotRunning);
        }
        match self.answer(dev, 1000) {
            Some(v) if v & STATUS == 0 => {}
            _ => return Err(Error::NotReady(self.read(dev, reg::C2PMSG_64))),
        }
        dev.put(self.b.ring, &[0; RING_SIZE as usize]);
        dev.flush();
        dev.write(self.mp0 + reg::C2PMSG_69, self.b.ring as u32);
        dev.write(self.mp0 + reg::C2PMSG_70, (self.b.ring >> 32) as u32);
        dev.write(self.mp0 + reg::C2PMSG_71, RING_SIZE);
        dev.write(self.mp0 + reg::C2PMSG_64, INIT_KM_RING);
        dev.delay_us(20_000);
        match self.answer(dev, 1000) {
            Some(v) if v & STATUS == 0 => Ok(()),
            Some(v) => Err(Error::Ring(v)),
            None => Err(Error::Ring(self.read(dev, reg::C2PMSG_64))),
        }
    }

    /// Take the rings away (one left by an earlier driver, say).
    pub fn destroy_rings(&mut self, card: &mut impl Card) -> Option<u32> {
        card.write(self.mp0 + reg::C2PMSG_64, DESTROY_RINGS);
        card.delay_us(20_000);
        self.answer(card, 1000)
    }

    /// Send command `id` with `args` and wait for it (up to two seconds).
    pub fn submit(&mut self, dev: &mut (impl Card + Memory), id: u32, args: &[u32]) -> Result<Response, Error> {
        let mut buf = [0u8; BUFFER];
        buf[8..12].copy_from_slice(&id.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            buf[28 + 4 * i..32 + 4 * i].copy_from_slice(&a.to_le_bytes());
        }
        dev.put(self.b.command, &buf);
        self.fence = self.fence.wrapping_add(1).max(1);
        let wptr = self.read(dev, reg::C2PMSG_67) % (RING_SIZE / 4);
        let mut frame = [0u8; FRAME as usize];
        let words = [
            self.b.command as u32,
            (self.b.command >> 32) as u32,
            0,
            self.b.fence as u32,
            (self.b.fence >> 32) as u32,
            self.fence,
        ];
        for (i, w) in words.iter().enumerate() {
            frame[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        dev.put(self.b.ring + u64::from(wptr) * 4, &frame);
        dev.flush();
        dev.write(self.mp0 + reg::C2PMSG_67, (wptr + FRAME / 4) % (RING_SIZE / 4));
        let mut done = false;
        for _ in 0..20_000 {
            if dev.get32(self.b.fence) == self.fence {
                done = true;
                break;
            }
            dev.delay_us(100);
        }
        if !done {
            return Err(Error::Timeout(id));
        }
        let at = self.b.command + RESPONSE_AT as u64;
        let r = Response {
            status: dev.get32(at),
            fw_addr: u64::from(dev.get32(at + 8)) | (u64::from(dev.get32(at + 12)) << 32),
            tmr_size: dev.get32(at + 16),
        };
        if r.status != 0 {
            return Err(Error::Status(id, r.status));
        }
        Ok(r)
    }

    fn image(&mut self, dev: &mut impl Memory, image: &[u8]) -> Result<(), Error> {
        if image.len() as u64 > self.b.image_size {
            return Err(Error::TooBig);
        }
        dev.put(self.b.image, image);
        Ok(())
    }

    /// Give it the TOC; the TMR size it asks for.
    pub fn load_toc(&mut self, dev: &mut (impl Card + Memory), toc: &[u8]) -> Result<u32, Error> {
        self.image(dev, toc)?;
        let a = self.b.image;
        Ok(self.submit(dev, LOAD_TOC, &[a as u32, (a >> 32) as u32, toc.len() as u32])?.tmr_size)
    }

    /// The trusted memory region: at GPU address `gpu`, system address
    /// `system`, `size` bytes.
    pub fn setup_tmr(&mut self, dev: &mut (impl Card + Memory), gpu: u64, system: u64, size: u32) -> Result<(), Error> {
        let args = [gpu as u32, (gpu >> 32) as u32, size, TMR_SYSTEM_ADDRESS, system as u32, (system >> 32) as u32];
        self.submit(dev, SETUP_TMR, &args).map(|_| ())
    }

    /// Load a firmware image of type `kind`; where it went.
    pub fn load_ip_fw(&mut self, dev: &mut (impl Card + Memory), kind: u32, image: &[u8]) -> Result<u64, Error> {
        self.image(dev, image)?;
        let a = self.b.image;
        Ok(self.submit(dev, LOAD_IP_FW, &[a as u32, (a >> 32) as u32, image.len() as u32, kind])?.fw_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    const MP0: u32 = 0x16000;
    const BASE: u64 = 0xF4_0000_0000;

    /// A PSP: registers, the GPU's memory, and the trusted OS answering
    /// its ring.
    struct Sim {
        r: BTreeMap<u32, u32>,
        mem: Vec<u8>,
        flushed: bool,
        ring: Option<u64>,
        tmr: Option<(u64, u64, u32)>,
        loaded: Vec<(u32, Vec<u8>)>,
        commands: Vec<u32>,
    }

    impl Sim {
        fn new() -> Self {
            let mut r = BTreeMap::new();
            r.insert(MP0 + reg::C2PMSG_81, 0x1234);
            r.insert(MP0 + reg::C2PMSG_64, RESPONSE);
            Sim { r, mem: vec![0; 4 << 20], flushed: false, ring: None, tmr: None, loaded: vec![], commands: vec![] }
        }
        fn word(&self, gpu: u64) -> u32 {
            let at = (gpu - BASE) as usize;
            u32::from_le_bytes(self.mem[at..at + 4].try_into().unwrap())
        }
        fn set(&mut self, gpu: u64, v: u32) {
            let at = (gpu - BASE) as usize;
            self.mem[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        /// The trusted OS runs the frame before the write pointer.
        fn run(&mut self, wptr: u32) {
            assert!(self.flushed, "the frame wasn't flushed");
            let ring = self.ring.expect("no ring");
            let frame = ring + u64::from((wptr + RING_SIZE / 4 - 16) % (RING_SIZE / 4)) * 4;
            let cmd = u64::from(self.word(frame)) | (u64::from(self.word(frame + 4)) << 32);
            let fence = u64::from(self.word(frame + 12)) | (u64::from(self.word(frame + 16)) << 32);
            let value = self.word(frame + 20);
            let id = self.word(cmd + 8);
            let arg = |s: &Self, i: u64| s.word(cmd + 28 + 4 * i);
            self.commands.push(id);
            let resp = cmd + RESPONSE_AT as u64;
            match id {
                LOAD_TOC => self.set(resp + 16, 0xA0_0000),
                SETUP_TMR => {
                    assert_eq!(arg(self, 3), TMR_SYSTEM_ADDRESS);
                    let gpu = u64::from(arg(self, 0)) | (u64::from(arg(self, 1)) << 32);
                    let sys = u64::from(arg(self, 4)) | (u64::from(arg(self, 5)) << 32);
                    self.tmr = Some((gpu, sys, arg(self, 2)));
                }
                LOAD_IP_FW if self.tmr.is_none() => self.set(resp, 0xFFFF_0007),
                LOAD_IP_FW => {
                    let at = (u64::from(arg(self, 0)) | (u64::from(arg(self, 1)) << 32)) - BASE;
                    let n = arg(self, 2) as usize;
                    let image = self.mem[at as usize..at as usize + n].to_vec();
                    self.loaded.push((arg(self, 3), image));
                    self.set(resp + 8, 0x5E30_0000);
                    self.set(resp + 12, 0x20);
                }
                _ => self.set(resp, 0x100),
            }
            self.set(fence, value);
            self.flushed = false;
        }
    }

    impl Card for Sim {
        fn read(&mut self, reg: u32) -> u32 {
            self.r.get(&reg).copied().unwrap_or(0)
        }
        fn write(&mut self, reg: u32, v: u32) {
            self.r.insert(reg, v);
            if reg == MP0 + reg::C2PMSG_64 {
                if v == INIT_KM_RING {
                    let lo = self.read(MP0 + reg::C2PMSG_69);
                    let hi = self.read(MP0 + reg::C2PMSG_70);
                    assert_eq!(self.read(MP0 + reg::C2PMSG_71), RING_SIZE);
                    self.ring = Some(u64::from(lo) | (u64::from(hi) << 32));
                }
                self.r.insert(reg, RESPONSE);
            }
            if reg == MP0 + reg::C2PMSG_67 {
                self.run(v);
            }
        }
        fn delay_us(&mut self, _: u32) {}
    }

    impl Memory for Sim {
        fn put(&mut self, gpu: u64, data: &[u8]) {
            let at = (gpu - BASE) as usize;
            self.mem[at..at + data.len()].copy_from_slice(data);
            self.flushed = false;
        }
        fn get32(&mut self, gpu: u64) -> u32 {
            self.word(gpu)
        }
        fn flush(&mut self) {
            self.flushed = true;
        }
    }

    fn buffers() -> Buffers {
        Buffers {
            ring: BASE,
            command: BASE + 0x1000,
            fence: BASE + 0x2000,
            image: BASE + 0x10_0000,
            image_size: 1 << 20,
        }
    }

    #[test]
    fn loads_a_firmware() {
        let mut s = Sim::new();
        let mut p = Psp::new(MP0, buffers());
        p.create_ring(&mut s).unwrap();
        assert_eq!(s.ring, Some(BASE));
        assert_eq!(p.load_toc(&mut s, &[1, 2, 3, 4]), Ok(0xA0_0000));
        p.setup_tmr(&mut s, 0xF4_1E00_0000, 0x20_5E00_0000, 0xA0_0000).unwrap();
        assert_eq!(s.tmr, Some((0xF4_1E00_0000, 0x20_5E00_0000, 0xA0_0000)));
        let image: Vec<u8> = (0..0x3A720u32).map(|i| i as u8).collect();
        assert_eq!(p.load_ip_fw(&mut s, FW_DMUB, &image), Ok(0x20_5E30_0000));
        assert_eq!(s.loaded, [(FW_DMUB, image)]);
        assert_eq!(s.commands, [LOAD_TOC, SETUP_TMR, LOAD_IP_FW]);
        // The ring wraps: 64 frames fit, the 65th goes first again.
        for _ in 0..70 {
            p.setup_tmr(&mut s, 0xF4_1E00_0000, 0x20_5E00_0000, 0xA0_0000).unwrap();
        }
        assert_eq!(s.read(MP0 + reg::C2PMSG_67), (73 * 16) % 1024);
    }

    #[test]
    fn says_what_went_wrong() {
        let mut s = Sim::new();
        let mut p = Psp::new(MP0, buffers());
        p.create_ring(&mut s).unwrap();
        // Firmware before a TMR: the PSP's status comes back.
        assert_eq!(p.load_ip_fw(&mut s, FW_DMUB, &[0; 64]), Err(Error::Status(LOAD_IP_FW, 0xFFFF_0007)));
        assert_eq!(p.load_ip_fw(&mut s, FW_DMUB, &vec![0; 2 << 20]), Err(Error::TooBig));
        assert_eq!(p.submit(&mut s, 0x99, &[]), Err(Error::Status(0x99, 0x100)));
        // No trusted OS; one that isn't ready.
        let mut s = Sim::new();
        s.r.insert(MP0 + reg::C2PMSG_81, 0);
        assert_eq!(Psp::new(MP0, buffers()).create_ring(&mut s), Err(Error::NotRunning));
        let mut s = Sim::new();
        s.r.insert(MP0 + reg::C2PMSG_64, 0);
        assert_eq!(Psp::new(MP0, buffers()).create_ring(&mut s), Err(Error::NotReady(0)));
    }

    #[test]
    fn the_toc_file() {
        let mut b = vec![0u8; 0x100 + 8];
        b[0x14..0x18].copy_from_slice(&8u32.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&0x100u32.to_le_bytes());
        b[0x100..].copy_from_slice(b"TOC TOC ");
        assert_eq!(toc(&b), Some(&b"TOC TOC "[..]));
        assert_eq!(toc(&b[..0x104]), None);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/psp_13_0_5_toc.bin");
        if let Ok(b) = std::fs::read(path) {
            assert!(toc(&b).is_some_and(|t| !t.is_empty()));
        }
    }
}
