// SPDX-License-Identifier: MIT OR Apache-2.0

//! An AtomBIOS interpreter (ADR 0171, M32 phase 4, step 4): running the
//! VBIOS's command tables, as Slate runs ACPI's AML (ASIC init, power
//! gating, the SMU's clock facts; on older and discrete cards also the
//! PHYs and the pixel clock). Raphael's VBIOS has no PHY or pixel clock
//! tables: on DCN 3.1 those are DMCUB's (ADR 0171's addendum).
//!
//! The facts come from amdgpu's atom.h and atom.c (Linux v7.2.12, read as
//! documentation, ADR 0157's addendum); this is Slate's own interpreter:
//!
//! - A command table: its size (word 0), its workspace size in dwords
//!   (byte 4), its parameter space size in bytes (byte 5, bits 6:0), then
//!   code from byte 6.
//! - An instruction: an opcode byte (1 to 126); most then an attribute
//!   byte: bits 2:0 the source's kind (register, parameter space,
//!   workspace, framebuffer scratch, data table, immediate, PLL, MC),
//!   bits 5:3 the source's alignment (a dword, a word at bit 0, 8 or 16, a
//!   byte at bit 0, 8, 16 or 24), bits 7:6 which part of the destination
//!   (for a word source: its word at bit 0, 8, 16, or the whole dword; for
//!   a byte source: its byte at 0, 8, 16, 24). The opcode gives the
//!   destination's kind.
//! - An operand: a register is a 16-bit index plus the register block;
//!   parameter space, workspace, scratch, PLL and MC an 8-bit index; the
//!   data table a 16-bit offset into the data block; an immediate a dword,
//!   word or byte as its alignment says. Workspace indices 40h to 48h are
//!   the quotient, the remainder, the data block, the shift (and the masks
//!   made of it), the scratch window, the I/O attributes and the register
//!   block.
//! - A value read is masked and shifted down by its alignment; a value
//!   written is shifted up and merged into what was there.

/// What the interpreter reaches: the card's registers (32-bit words), and
/// time.
pub trait Card {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn delay_us(&mut self, us: u32);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No such command table.
    NoTable(u8),
    /// An opcode the interpreter doesn't know (or one AtomBIOS never
    /// defined behaviour for: REPEAT, SAVEREG, RESTOREREG).
    Opcode { table: u16, at: u16, op: u8 },
    /// The code ran past the image.
    Truncated,
    /// Tables calling tables more than 32 deep.
    TooDeep,
    /// More than the instruction budget: a table waiting for a register
    /// that never changes.
    Stuck { table: u16 },
    /// PCI or system I/O space, or an indirect I/O program that isn't
    /// there.
    Io,
}

/// Operand kinds (atom.h, ATOM_ARG_*).
const REG: u8 = 0;
const PS: u8 = 1;
const WS: u8 = 2;
const FB: u8 = 3;
const ID: u8 = 4;
const IMM: u8 = 5;
const PLL: u8 = 6;
const MC: u8 = 7;

/// Alignments (ATOM_SRC_*): their masks and shifts.
const MASK: [u32; 8] = [0xFFFF_FFFF, 0xFFFF, 0xFF_FF00, 0xFFFF_0000, 0xFF, 0xFF00, 0xFF_0000, 0xFF00_0000];
const SHIFT: [u32; 8] = [0, 0, 8, 16, 0, 8, 16, 24];
const DWORD: u8 = 0;

/// A destination's alignment: by the source's alignment (a dword, a word,
/// a byte) and the attribute's bits 7:6.
fn dst_align(attr: u8) -> u8 {
    let (src, part) = ((attr >> 3) & 7, attr >> 6);
    match src {
        0 => DWORD,
        1..=3 => [1, 2, 3, 0][usize::from(part)],
        _ => 4 + part,
    }
}

/// The destination part the CLEAR and shift-by-constant opcodes use: the
/// source alignment's own (atom.c's `atom_def_dst`).
fn own_part(attr: u8) -> u8 {
    let a = attr & 0x38;
    a | ([0u8, 0, 1, 2, 0, 1, 2, 3][usize::from(a >> 3)] << 6)
}

/// Workspace indices with meanings (ATOM_WS_*).
const WS_QUOTIENT: u8 = 0x40;
const WS_REMAINDER: u8 = 0x41;
const WS_DATAPTR: u8 = 0x42;
const WS_SHIFT: u8 = 0x43;
const WS_OR_MASK: u8 = 0x44;
const WS_AND_MASK: u8 = 0x45;
const WS_FB_WINDOW: u8 = 0x46;
const WS_ATTRIBUTES: u8 = 0x47;
const WS_REGPTR: u8 = 0x48;

/// The data list's indirect I/O entry (atomfirmware.h's
/// `indirectioaccess`, the 24th).
const DATA_INDIRECT_IO: usize = 23;

/// Instructions a call may take before it counts as stuck (a register
/// waited for that never changes): far more than any real table needs.
pub const BUDGET: u32 = 4_000_000;

/// The registers' access mode (atom.h, ATOM_IO_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoMode {
    Mmio,
    Pci,
    SysIo,
    /// An indirect I/O program, by its ID.
    Indirect(u8),
}

/// The interpreter: a VBIOS image and the state its tables share.
#[derive(Debug)]
pub struct Interp<'a> {
    rom: &'a [u8],
    command: usize,
    data: usize,
    /// The framebuffer scratch area (`ATOM_ARG_FB`), in dwords.
    pub scratch: alloc::vec::Vec<u32>,
    data_block: u32,
    reg_block: u32,
    fb_base: u32,
    io: IoMode,
    io_attr: u32,
    shift: u8,
    divmul: [u32; 2],
    above: bool,
    equal: bool,
    budget: u32,
    depth: u32,
    /// Indirect I/O programs by ID: where each starts.
    iio: [u16; 256],
}

/// One table's own state.
struct Frame<'p> {
    start: usize,
    ps: &'p mut [u32],
    ws: alloc::vec::Vec<u32>,
}

/// An operand: where it is.
#[derive(Clone, Copy, Debug)]
enum Loc {
    Reg(u32),
    Ps(u8),
    Ws(u8),
    Fb(u8),
    Id(u16),
    Imm(u32),
    /// PLL and MC spaces (their index read and dropped: these GPUs have
    /// neither).
    Pll,
    Mc,
}

impl<'a> Interp<'a> {
    /// The interpreter for a VBIOS image ([`crate::atom::Rom`]), with
    /// `scratch_dwords` of scratch.
    pub fn new(rom: &crate::atom::Rom<'a>, scratch_dwords: usize) -> Interp<'a> {
        let image = rom.image;
        let header = usize::from(crate::u16_at(image, 0x48).unwrap_or(0));
        let command = usize::from(crate::u16_at(image, header + 0x1E).unwrap_or(0));
        let data = usize::from(crate::u16_at(image, header + 0x20).unwrap_or(0));
        let mut i = Interp {
            rom: image,
            command,
            data,
            scratch: alloc::vec![0; scratch_dwords],
            data_block: 0,
            reg_block: 0,
            fb_base: 0,
            io: IoMode::Mmio,
            io_attr: 0,
            shift: 0,
            divmul: [0; 2],
            above: false,
            equal: false,
            budget: 0,
            depth: 0,
            iio: [0; 256],
        };
        i.index_iio();
        i
    }

    /// The indirect I/O programs (atom.c's `atom_index_iio`): after the
    /// data table's 4-byte header, START (1) and an ID, then the program up
    /// to END (9), each opcode its length (NOP 1, START 2, the others 3 or
    /// 4), END taking 3 bytes.
    fn index_iio(&mut self) {
        let Some(table) = self.u16(self.data + 4 + 2 * DATA_INDIRECT_IO).filter(|&t| t != 0) else { return };
        const LEN: [usize; 10] = [1, 2, 3, 3, 3, 3, 4, 4, 4, 3];
        let mut at = usize::from(table) + 4;
        while self.u8(at) == Some(1) {
            let Some(id) = self.u8(at + 1) else { return };
            self.iio[usize::from(id)] = (at + 2) as u16;
            at += 2;
            for _ in 0..4096 {
                match self.u8(at) {
                    Some(9) => break,
                    Some(op) if usize::from(op) < LEN.len() => at += LEN[usize::from(op)],
                    _ => return,
                }
            }
            at += 3;
        }
    }

    fn u8(&self, at: usize) -> Option<u8> {
        self.rom.get(at).copied()
    }

    fn u16(&self, at: usize) -> Option<u16> {
        crate::u16_at(self.rom, at)
    }

    fn u32(&self, at: usize) -> Option<u32> {
        crate::u32_at(self.rom, at)
    }

    /// Where command table `index` is, if it exists (within the master
    /// command list's own size).
    fn table(&self, index: u8) -> Option<usize> {
        let size = usize::from(self.u16(self.command)?);
        let at = 4 + 2 * usize::from(index);
        (at + 2 <= size).then(|| self.u16(self.command + at)).flatten().filter(|&t| t != 0).map(usize::from)
    }

    /// Whether command table `index` exists.
    pub fn has(&self, index: u8) -> bool {
        self.table(index).is_some()
    }

    /// Run command table `index` with `params` (its parameter space, in
    /// dwords; the table writes its results back into it).
    pub fn execute(&mut self, card: &mut dyn Card, index: u8, params: &mut [u32]) -> Result<(), Error> {
        self.data_block = 0;
        self.reg_block = 0;
        self.fb_base = 0;
        self.io = IoMode::Mmio;
        self.divmul = [0; 2];
        self.budget = BUDGET;
        self.depth = 0;
        self.run(card, index, params)
    }

    fn run(&mut self, card: &mut dyn Card, index: u8, ps: &mut [u32]) -> Result<(), Error> {
        let start = self.table(index).ok_or(Error::NoTable(index))?;
        if self.depth >= 32 {
            return Err(Error::TooDeep);
        }
        self.depth += 1;
        let ws = usize::from(self.u8(start + 4).ok_or(Error::Truncated)?);
        let mut f = Frame { start, ps, ws: alloc::vec![0; ws] };
        let r = self.code(card, &mut f);
        self.depth -= 1;
        r
    }

    /// The table's code, from byte 6 to EOT.
    fn code(&mut self, card: &mut dyn Card, f: &mut Frame<'_>) -> Result<(), Error> {
        let mut pc = f.start + 6;
        loop {
            if self.budget == 0 {
                return Err(Error::Stuck { table: f.start as u16 });
            }
            self.budget -= 1;
            let at = pc;
            let op = self.u8(pc).ok_or(Error::Truncated)?;
            pc += 1;
            let bad = Error::Opcode { table: f.start as u16, at: (at - f.start) as u16, op };
            // The destination kind of the six-kind families: REG, PS, WS,
            // FB, PLL, MC, in that order.
            let kind = |base: u8| [REG, PS, WS, FB, PLL, MC][usize::from(op - base)];
            match op {
                1..=6 => self.binary(card, f, &mut pc, kind(1), |_, s| s, true)?,
                7..=12 => self.binary(card, f, &mut pc, kind(7), |d, s| d & s, false)?,
                13..=18 => self.binary(card, f, &mut pc, kind(13), |d, s| d | s, false)?,
                19..=24 => self.shift_by(card, f, &mut pc, kind(19), true)?,
                25..=30 => self.shift_by(card, f, &mut pc, kind(25), false)?,
                31..=36 => {
                    let (d, s) = self.two(card, f, &mut pc, kind(31))?;
                    self.divmul[0] = d.wrapping_mul(s);
                }
                37..=42 => {
                    let (d, s) = self.two(card, f, &mut pc, kind(37))?;
                    // (Dividing by 0 gives 0 and 0, as AtomBIOS expects.)
                    self.divmul = [d.checked_div(s).unwrap_or(0), d.checked_rem(s).unwrap_or(0)];
                }
                43..=48 => self.binary(card, f, &mut pc, kind(43), u32::wrapping_add, false)?,
                49..=54 => self.binary(card, f, &mut pc, kind(49), u32::wrapping_sub, false)?,
                55 => {
                    let port = self.u16(pc).ok_or(Error::Truncated)?;
                    pc += 2;
                    self.io = if port == 0 { IoMode::Mmio } else { IoMode::Indirect(port as u8) };
                }
                56 | 57 => {
                    pc += 1;
                    self.io = if op == 56 { IoMode::Pci } else { IoMode::SysIo };
                }
                58 => {
                    self.reg_block = u32::from(self.u16(pc).ok_or(Error::Truncated)?);
                    pc += 2;
                }
                59 => {
                    let attr = self.u8(pc).ok_or(Error::Truncated)?;
                    pc += 1;
                    self.fb_base = self.src(card, f, &mut pc, attr)?;
                }
                60..=65 => {
                    let (d, s) = self.two(card, f, &mut pc, kind(60))?;
                    (self.equal, self.above) = (d == s, d > s);
                }
                66 => pc = self.switch(card, f, pc)?,
                67..=73 => {
                    let target = usize::from(self.u16(pc).ok_or(Error::Truncated)?);
                    pc += 2;
                    let (a, e) = (self.above, self.equal);
                    // ALWAYS, EQUAL, BELOW, ABOVE, BELOW OR EQUAL, ABOVE
                    // OR EQUAL, NOT EQUAL (atom.c's opcode table order).
                    let take = [true, e, !(a || e), a, !a, a || e, !e][usize::from(op - 67)];
                    if take {
                        pc = f.start + target;
                    }
                }
                74..=79 => {
                    let (d, s) = self.two(card, f, &mut pc, kind(74))?;
                    self.equal = d & s == 0;
                }
                80 | 81 => {
                    let n = u32::from(self.u8(pc).ok_or(Error::Truncated)?);
                    pc += 1;
                    card.delay_us(if op == 80 { n * 1000 } else { n });
                }
                82 => {
                    let idx = self.u8(pc).ok_or(Error::Truncated)?;
                    pc += 1;
                    if self.has(idx) {
                        // The callee's parameters start past the caller's own
                        // (byte 5's size, in dwords).
                        let skip = usize::from(self.u8(f.start + 5).unwrap_or(0) & 0x7F) / 4;
                        let rest = f.ps.get_mut(skip..).unwrap_or(&mut []);
                        self.run(card, idx, rest)?;
                    }
                }
                84..=89 => {
                    let attr = own_part(self.u8(pc).ok_or(Error::Truncated)?);
                    pc += 1;
                    let (loc, saved, _) = self.dst(card, f, &mut pc, kind(84), attr)?;
                    self.put(card, f, loc, attr, 0, saved)?;
                }
                90 | 91 => {
                    if op == 91 {
                        return Ok(());
                    }
                }
                92..=97 => {
                    let attr = self.u8(pc).ok_or(Error::Truncated)?;
                    pc += 1;
                    let (loc, saved, d) = self.dst(card, f, &mut pc, kind(92), attr)?;
                    let mask = self.immediate(&mut pc, (attr >> 3) & 7)?;
                    let s = self.src(card, f, &mut pc, attr)?;
                    self.put(card, f, loc, attr, (d & mask) | s, saved)?;
                }
                98 | 121 => pc += 1,
                99 => {}
                102 => {
                    let idx = self.u8(pc).ok_or(Error::Truncated)?;
                    pc += 1;
                    self.data_block = match idx {
                        0 => 0,
                        255 => f.start as u32,
                        i => u32::from(self.u16(self.data + 4 + 2 * usize::from(i)).unwrap_or(0)),
                    };
                }
                103..=108 => self.binary(card, f, &mut pc, kind(103), |d, s| d ^ s, false)?,
                109..=120 => {
                    // SHL and SHR: the whole destination shifted by the
                    // source, then taken at the destination's alignment.
                    let left = op <= 114;
                    let attr = self.u8(pc).ok_or(Error::Truncated)?;
                    pc += 1;
                    let (loc, saved, _) = self.dst(card, f, &mut pc, kind(if left { 109 } else { 115 }), attr)?;
                    let by = self.src(card, f, &mut pc, attr)?;
                    let whole =
                        if left { saved.checked_shl(by).unwrap_or(0) } else { saved.checked_shr(by).unwrap_or(0) };
                    let a = usize::from(dst_align(attr));
                    self.put(card, f, loc, attr, (whole & MASK[a]) >> SHIFT[a], saved)?;
                }
                122 => {
                    let n = usize::from(self.u16(pc).ok_or(Error::Truncated)?);
                    pc += n + 2;
                }
                123 | 124 => {
                    let (d, s) = self.two(card, f, &mut pc, if op == 123 { PS } else { WS })?;
                    let p = u64::from(d) * u64::from(s);
                    self.divmul = [p as u32, (p >> 32) as u32];
                }
                125 | 126 => {
                    let (d, s) = self.two(card, f, &mut pc, if op == 125 { PS } else { WS })?;
                    self.divmul = if s == 0 {
                        [0, 0]
                    } else {
                        let q = (u64::from(d) | (u64::from(self.divmul[1]) << 32)) / u64::from(s);
                        [q as u32, (q >> 32) as u32]
                    };
                }
                _ => return Err(bad),
            }
        }
    }

    /// dst = f(dst, src) for the two-operand families; MOVE (`plain`)
    /// doesn't read a dword destination first.
    fn binary(
        &mut self,
        card: &mut dyn Card,
        f: &mut Frame<'_>,
        pc: &mut usize,
        kind: u8,
        op: impl Fn(u32, u32) -> u32,
        plain: bool,
    ) -> Result<(), Error> {
        let attr = self.u8(*pc).ok_or(Error::Truncated)?;
        *pc += 1;
        let (loc, saved, d) = if plain && (attr >> 3) & 7 == DWORD {
            let loc = self.loc(pc, kind, attr)?;
            (loc, 0, 0)
        } else {
            self.dst(card, f, pc, kind, attr)?
        };
        let s = self.src(card, f, pc, attr)?;
        self.put(card, f, loc, attr, op(d, s), saved)
    }

    /// SHIFT_LEFT and SHIFT_RIGHT: by a constant byte, at the source
    /// alignment's own part.
    fn shift_by(
        &mut self,
        card: &mut dyn Card,
        f: &mut Frame<'_>,
        pc: &mut usize,
        kind: u8,
        left: bool,
    ) -> Result<(), Error> {
        let attr = own_part(self.u8(*pc).ok_or(Error::Truncated)?);
        *pc += 1;
        let (loc, saved, d) = self.dst(card, f, pc, kind, attr)?;
        let by = u32::from(self.u8(*pc).ok_or(Error::Truncated)?);
        *pc += 1;
        let v = if left { d.checked_shl(by).unwrap_or(0) } else { d.checked_shr(by).unwrap_or(0) };
        self.put(card, f, loc, attr, v, saved)
    }

    /// The destination's and the source's values, for the opcodes that
    /// write neither back.
    fn two(&mut self, card: &mut dyn Card, f: &mut Frame<'_>, pc: &mut usize, kind: u8) -> Result<(u32, u32), Error> {
        let attr = self.u8(*pc).ok_or(Error::Truncated)?;
        *pc += 1;
        let (_, _, d) = self.dst(card, f, pc, kind, attr)?;
        let s = self.src(card, f, pc, attr)?;
        Ok((d, s))
    }

    /// SWITCH: the source, then cases (63h, a value of the source's size,
    /// a target) until 5A5Ah.
    fn switch(&mut self, card: &mut dyn Card, f: &mut Frame<'_>, mut pc: usize) -> Result<usize, Error> {
        let attr = self.u8(pc).ok_or(Error::Truncated)?;
        pc += 1;
        let s = self.src(card, f, &mut pc, attr)?;
        loop {
            if self.u16(pc).ok_or(Error::Truncated)? == 0x5A5A {
                return Ok(pc + 2);
            }
            if self.u8(pc) != Some(0x63) {
                return Err(Error::Opcode { table: f.start as u16, at: (pc - f.start) as u16, op: 66 });
            }
            pc += 1;
            let v = self.immediate(&mut pc, (attr >> 3) & 7)?;
            let target = usize::from(self.u16(pc).ok_or(Error::Truncated)?);
            if v == s {
                return Ok(f.start + target);
            }
            pc += 2;
        }
    }

    /// An immediate of the alignment's size, unshifted.
    fn immediate(&self, pc: &mut usize, align: u8) -> Result<u32, Error> {
        let (v, n) = match align {
            0 => (self.u32(*pc), 4),
            1..=3 => (self.u16(*pc).map(u32::from), 2),
            _ => (self.u8(*pc).map(u32::from), 1),
        };
        *pc += n;
        v.ok_or(Error::Truncated)
    }

    /// Decode an operand of `kind` at `pc`.
    fn loc(&self, pc: &mut usize, kind: u8, attr: u8) -> Result<Loc, Error> {
        let byte = |pc: &mut usize| -> Result<u8, Error> {
            let v = self.u8(*pc).ok_or(Error::Truncated)?;
            *pc += 1;
            Ok(v)
        };
        Ok(match kind {
            REG | ID => {
                let v = self.u16(*pc).ok_or(Error::Truncated)?;
                *pc += 2;
                if kind == REG { Loc::Reg(u32::from(v)) } else { Loc::Id(v) }
            }
            PS => Loc::Ps(byte(pc)?),
            WS => Loc::Ws(byte(pc)?),
            FB => Loc::Fb(byte(pc)?),
            PLL => {
                byte(pc)?;
                Loc::Pll
            }
            MC => {
                byte(pc)?;
                Loc::Mc
            }
            IMM => Loc::Imm(self.immediate(pc, (attr >> 3) & 7)?),
            _ => return Err(Error::Io),
        })
    }

    /// A location's whole 32-bit value.
    fn get(&mut self, card: &mut dyn Card, f: &Frame<'_>, loc: Loc) -> Result<u32, Error> {
        Ok(match loc {
            Loc::Reg(r) => {
                let r = r + self.reg_block;
                match self.io {
                    IoMode::Mmio => card.read(r),
                    IoMode::Indirect(id) => self.indirect(card, id, r, 0)?,
                    _ => return Err(Error::Io),
                }
            }
            Loc::Ps(i) => f.ps.get(usize::from(i)).copied().unwrap_or(0),
            Loc::Ws(i) => match i {
                WS_QUOTIENT => self.divmul[0],
                WS_REMAINDER => self.divmul[1],
                WS_DATAPTR => self.data_block,
                WS_SHIFT => u32::from(self.shift),
                WS_OR_MASK => 1u32.checked_shl(u32::from(self.shift)).unwrap_or(0),
                WS_AND_MASK => !1u32.checked_shl(u32::from(self.shift)).unwrap_or(0),
                WS_FB_WINDOW => self.fb_base,
                WS_ATTRIBUTES => self.io_attr,
                WS_REGPTR => self.reg_block,
                i => f.ws.get(usize::from(i)).copied().unwrap_or(0),
            },
            Loc::Fb(i) => self.scratch.get(self.fb_base as usize / 4 + usize::from(i)).copied().unwrap_or(0),
            Loc::Id(o) => self.u32(o as usize + self.data_block as usize).unwrap_or(0),
            Loc::Imm(v) => v,
            // No PLL or MC spaces on these GPUs (amdgpu's are stubs).
            Loc::Pll | Loc::Mc => 0,
        })
    }

    /// A destination: its location, its whole value, its aligned value.
    fn dst(
        &mut self,
        card: &mut dyn Card,
        f: &mut Frame<'_>,
        pc: &mut usize,
        kind: u8,
        attr: u8,
    ) -> Result<(Loc, u32, u32), Error> {
        let loc = self.loc(pc, kind, attr)?;
        let whole = self.get(card, f, loc)?;
        let a = usize::from(dst_align(attr));
        Ok((loc, whole, (whole & MASK[a]) >> SHIFT[a]))
    }

    /// A source: its aligned value (an immediate as it is).
    fn src(&mut self, card: &mut dyn Card, f: &mut Frame<'_>, pc: &mut usize, attr: u8) -> Result<u32, Error> {
        let kind = attr & 7;
        let loc = self.loc(pc, kind, attr)?;
        if let Loc::Imm(v) = loc {
            return Ok(v);
        }
        let a = usize::from((attr >> 3) & 7);
        Ok((self.get(card, f, loc)? & MASK[a]) >> SHIFT[a])
    }

    /// Write `value` at the destination's alignment into `saved`.
    fn put(
        &mut self,
        card: &mut dyn Card,
        f: &mut Frame<'_>,
        loc: Loc,
        attr: u8,
        value: u32,
        saved: u32,
    ) -> Result<(), Error> {
        let a = usize::from(dst_align(attr));
        let v = ((value << SHIFT[a]) & MASK[a]) | (saved & !MASK[a]);
        match loc {
            Loc::Reg(r) => {
                let r = r + self.reg_block;
                match self.io {
                    // Register 0 (MM_INDEX) takes a byte address.
                    IoMode::Mmio => card.write(r, if r == 0 { v << 2 } else { v }),
                    IoMode::Indirect(id) => {
                        self.indirect(card, id, r, v)?;
                    }
                    _ => return Err(Error::Io),
                }
            }
            Loc::Ps(i) => {
                if let Some(p) = f.ps.get_mut(usize::from(i)) {
                    *p = v;
                }
            }
            Loc::Ws(i) => match i {
                WS_QUOTIENT => self.divmul[0] = v,
                WS_REMAINDER => self.divmul[1] = v,
                WS_DATAPTR => self.data_block = v,
                WS_SHIFT => self.shift = v as u8,
                WS_OR_MASK | WS_AND_MASK => {}
                WS_FB_WINDOW => self.fb_base = v,
                WS_ATTRIBUTES => self.io_attr = v,
                WS_REGPTR => self.reg_block = v,
                i => {
                    if let Some(w) = f.ws.get_mut(usize::from(i)) {
                        *w = v;
                    }
                }
            },
            Loc::Fb(i) => {
                let at = self.fb_base as usize / 4 + usize::from(i);
                if let Some(s) = self.scratch.get_mut(at) {
                    *s = v;
                }
            }
            Loc::Id(_) | Loc::Imm(_) | Loc::Pll | Loc::Mc => {}
        }
        Ok(())
    }

    /// Run indirect I/O program `id` for register `index` (and `data`, a
    /// write's value): READ (2) and WRITE (3) take a register, CLEAR (4)
    /// and SET (5) a width and a position in a temporary, MOVE_INDEX (6),
    /// MOVE_ATTR (7) and MOVE_DATA (8) a width, a source position and a
    /// destination position, END (9) gives the temporary.
    fn indirect(&mut self, card: &mut dyn Card, id: u8, index: u32, data: u32) -> Result<u32, Error> {
        let mut at = usize::from(self.iio[usize::from(id)]);
        if at == 0 {
            return Err(Error::Io);
        }
        let mut temp: u32 = 0xCDCD_CDCD;
        let ones = |bits: u8| u32::MAX.checked_shr(32 - u32::from(bits)).unwrap_or(0);
        for _ in 0..4096 {
            let b = |k: usize| self.u8(at + k).ok_or(Error::Truncated);
            match b(0)? {
                0 => at += 1,
                2 => {
                    temp = card.read(u32::from(self.u16(at + 1).ok_or(Error::Truncated)?));
                    at += 3;
                }
                3 => {
                    card.write(u32::from(self.u16(at + 1).ok_or(Error::Truncated)?), temp);
                    at += 3;
                }
                4 => {
                    temp &= !(ones(b(1)?) << b(2)?);
                    at += 3;
                }
                5 => {
                    temp |= ones(b(1)?) << b(2)?;
                    at += 3;
                }
                op @ 6..=8 => {
                    let (w, from, to) = (ones(b(1)?), b(2)?, b(3)?);
                    let src = [index, self.io_attr, data][usize::from(op - 6)];
                    temp &= !(w << to);
                    temp |= ((src >> from) & w) << to;
                    at += 4;
                }
                9 => return Ok(temp),
                _ => return Err(Error::Io),
            }
        }
        Err(Error::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    /// Registers in a map; every write recorded.
    #[derive(Default)]
    struct Regs {
        r: BTreeMap<u32, u32>,
        writes: Vec<(u32, u32)>,
        waited: u32,
    }

    impl Card for Regs {
        fn read(&mut self, reg: u32) -> u32 {
            self.r.get(&reg).copied().unwrap_or(0)
        }
        fn write(&mut self, reg: u32, value: u32) {
            self.r.insert(reg, value);
            self.writes.push((reg, value));
        }
        fn delay_us(&mut self, us: u32) {
            self.waited += us;
        }
    }

    /// An image with command tables (each `(workspace, parameter bytes,
    /// code)`), a data table list holding `data` as entry 1 and an indirect
    /// I/O table `iio` (entry 23).
    fn image(tables: &[(u8, u8, &[u8])], data: &[u8], iio: &[u8]) -> Vec<u8> {
        let mut d = std::vec![0u8; 0x200];
        d[0..2].copy_from_slice(&[0x55, 0xAA]);
        d[0x48..0x4A].copy_from_slice(&0x80u16.to_le_bytes());
        d[0x84..0x88].copy_from_slice(b"ATOM");
        d[0x80 + 0x1E..0x80 + 0x20].copy_from_slice(&0x100u16.to_le_bytes());
        d[0x80 + 0x20..0x80 + 0x22].copy_from_slice(&0x180u16.to_le_bytes());
        d[0x100..0x102].copy_from_slice(&(4 + 2 * 32u16).to_le_bytes());
        d[0x180..0x182].copy_from_slice(&(4 + 2 * 32u16).to_le_bytes());
        let put = |d: &mut Vec<u8>, bytes: &[u8]| -> u16 {
            let at = d.len() as u16;
            d.extend_from_slice(bytes);
            at
        };
        for (i, (ws, ps, code)) in tables.iter().enumerate() {
            let mut t = Vec::from(((6 + code.len()) as u16).to_le_bytes());
            t.extend_from_slice(&[1, 1, *ws, *ps]);
            t.extend_from_slice(code);
            let at = put(&mut d, &t);
            d[0x104 + 2 * i..0x106 + 2 * i].copy_from_slice(&at.to_le_bytes());
        }
        let mut dt = Vec::from(((4 + data.len()) as u16).to_le_bytes());
        dt.extend_from_slice(&[1, 1]);
        dt.extend_from_slice(data);
        let at = put(&mut d, &dt);
        d[0x186..0x188].copy_from_slice(&at.to_le_bytes());
        let mut it = Vec::from(((4 + iio.len()) as u16).to_le_bytes());
        it.extend_from_slice(&[1, 1]);
        it.extend_from_slice(iio);
        let at = put(&mut d, &it);
        d[0x184 + 2 * DATA_INDIRECT_IO..0x186 + 2 * DATA_INDIRECT_IO].copy_from_slice(&at.to_le_bytes());
        d
    }

    fn run(img: &[u8], table: u8, ps: &mut [u32], regs: &mut Regs) -> Result<(), Error> {
        let rom = crate::atom::Rom::new(img).unwrap();
        let mut i = Interp::new(&rom, 64);
        i.execute(regs, table, ps)
    }

    // Attribute bytes: source kind | source alignment << 3 | part << 6.
    const fn attr(src: u8, align: u8, part: u8) -> u8 {
        src | (align << 3) | (part << 6)
    }

    #[test]
    fn moves_and_alignment() {
        let code = [
            // MOVE REG[10h] = IMM dword 11223344h
            1,
            attr(IMM, 0, 0),
            0x10,
            0,
            0x44,
            0x33,
            0x22,
            0x11,
            // MOVE REG[10h].byte8 = IMM byte AAh (part 1: the byte at 8)
            1,
            attr(IMM, 4, 1),
            0x10,
            0,
            0xAA,
            // MOVE PS[1] = REG[10h] word at 16 (into PS[1]'s low word)
            2,
            attr(REG, 3, 0),
            1,
            0x10,
            0,
            // MOVE REG[11h] = PS[0] (dword)
            1,
            attr(PS, 0, 0),
            0x11,
            0,
            0,
            91,
        ];
        let img = image(&[(0, 8, &code)], &[], &[]);
        let mut regs = Regs::default();
        let mut ps = [0xDEAD_BEEF, 0xFFFF_0000];
        run(&img, 0, &mut ps, &mut regs).unwrap();
        assert_eq!(regs.r[&0x10], 0x1122_AA44);
        assert_eq!(ps[1], 0xFFFF_1122);
        assert_eq!(regs.r[&0x11], 0xDEAD_BEEF);
    }

    #[test]
    fn arithmetic_compare_jump_and_loops() {
        // WS[0] = 0; loop: WS[0] += 3; COMPARE WS[0], 12; JUMP BELOW loop;
        // MUL WS[0], 5 -> quotient; MOVE PS[0] = quotient; DIV 0x10, 3 ->
        // PS[1] = remainder.
        let code = [
            3,
            attr(IMM, 0, 0),
            0,
            0,
            0,
            0,
            0, // 6: WS[0] = 0
            45,
            attr(IMM, 4, 0),
            0,
            3, // 13: ADD WS[0] += 3 (byte)
            62,
            attr(IMM, 4, 0),
            0,
            12, // 17: COMPARE WS[0], 12
            69,
            13,
            0, // 21: JUMP BELOW -> 13
            33,
            attr(IMM, 4, 0),
            0,
            5, // MUL WS[0] * 5
            2,
            attr(WS, 0, 0),
            0,
            WS_QUOTIENT, // PS[0] = quotient
            3,
            attr(IMM, 0, 0),
            1,
            0x10,
            0,
            0,
            0, // WS[1] = 16
            39,
            attr(IMM, 4, 0),
            1,
            3, // DIV WS[1] / 3
            2,
            attr(WS, 0, 0),
            1,
            WS_REMAINDER, // PS[1] = remainder
            91,
        ];
        let img = image(&[(2, 8, &code)], &[], &[]);
        let mut regs = Regs::default();
        let mut ps = [0u32; 2];
        run(&img, 0, &mut ps, &mut regs).unwrap();
        assert_eq!(ps, [60, 1]);
    }

    #[test]
    fn switch_calls_data_and_shifts() {
        // Table 1: PS[0] += 1.
        let callee = [44, attr(IMM, 4, 0), 0, 1, 91];
        // Table 0 (4 bytes of its own parameters: the callee sees PS[1]):
        // SWITCH PS[0] (byte) case 2 -> 20; else EOT. At 20: CALLTABLE 1;
        // SETDATABLOCK 1; MOVE PS[2] = ID[0] (the data table's first
        // dword); SHL PS[2] by 4; SHIFT_RIGHT PS[3] by 8.
        let code = [
            66,
            attr(PS, 4, 0),
            0,
            0x63,
            2,
            20,
            0,
            0x5A,
            0x5A, // 6..15
            91,
            0,
            0,
            0,
            0, // 15: EOT, padding to 20
            82,
            1, // 20: CALLTABLE 1
            102,
            1, // SETDATABLOCK 1
            2,
            attr(ID, 0, 0),
            2,
            4,
            0, // PS[2] = data[4..8] (after its header)
            110,
            attr(IMM, 0, 0),
            2,
            4,
            0,
            0,
            0, // SHL PS[2] (dword) by 4
            26,
            attr(0, 0, 0),
            3,
            8, // SHIFT_RIGHT PS[3] (dword) by 8
            91,
        ];
        let img = image(&[(0, 4, &code), (0, 4, &callee)], &[0x78, 0x56, 0x34, 0x12], &[]);
        let mut regs = Regs::default();
        let mut ps = [2u32, 41, 0, 0xABCD_EF00];
        run(&img, 0, &mut ps, &mut regs).unwrap();
        assert_eq!(ps, [2, 42, 0x2345_6780, 0x00AB_CDEF]);
        // Another case value: straight to EOT.
        let mut ps = [3u32, 41, 0, 0];
        run(&img, 0, &mut ps, &mut regs).unwrap();
        assert_eq!(ps[1], 41);
    }

    #[test]
    fn masks_tests_clears_delays_and_blocks() {
        let code = [
            58,
            0x00,
            0x01, // SETREGBLOCK 100h
            1,
            attr(IMM, 0, 0),
            0x20,
            0,
            0xFF,
            0xFF,
            0xFF,
            0xFF, // REG[120h] = FFFFFFFF
            // MASK REG[120h] (word0): & 0F0Fh | 0030h
            92,
            attr(IMM, 1, 0),
            0x20,
            0,
            0x0F,
            0x0F,
            0x30,
            0,
            // TEST REG[120h], 1000h -> equal (no bits in common)
            74,
            attr(IMM, 0, 0),
            0x20,
            0,
            0,
            0x10,
            0,
            0,
            // CLEAR PS[0] byte 8
            85,
            attr(0, 5, 0),
            0,
            80,
            2,
            81,
            7, // 2 ms, 7 µs
            91,
        ];
        let img = image(&[(0, 4, &code)], &[], &[]);
        let mut regs = Regs::default();
        let mut ps = [0x1122_3344u32];
        let rom = crate::atom::Rom::new(&img).unwrap();
        let mut i = Interp::new(&rom, 16);
        i.execute(&mut regs, 0, &mut ps).unwrap();
        assert_eq!(regs.r[&0x120], 0xFFFF_0F3F);
        assert!(i.equal);
        assert_eq!(ps[0], 0x1122_0044);
        assert_eq!(regs.waited, 2007);
    }

    #[test]
    fn indirect_io() {
        // Program 3: write the index to register 40h, then read 41h (a
        // read), or move the data into 41h (a write).
        let iio = [
            1, 3, // START 3
            4, 32, 0, // CLEAR all 32 bits (the temporary starts CDCDCDCDh)
            6, 16, 0, 0, // MOVE_INDEX 16 bits from 0 to 0
            3, 0x40, 0, // WRITE 40h
            2, 0x41, 0, // READ 41h
            9, 0, 0, // END
        ];
        let code = [
            55,
            3,
            0, // SETPORT ATI 3: indirect
            2,
            attr(REG, 0, 0),
            0,
            0x77,
            0, // PS[0] = REG[77h] (through program 3)
            55,
            0,
            0, // back to MMIO
            91,
        ];
        let img = image(&[(0, 4, &code)], &[], &iio);
        let mut regs = Regs::default();
        regs.r.insert(0x41, 0xCAFE);
        let mut ps = [0u32];
        run(&img, 0, &mut ps, &mut regs).unwrap();
        assert_eq!(ps[0], 0xCAFE);
        assert_eq!(regs.writes, [(0x40, 0x77)]);
    }

    #[test]
    fn errors() {
        let img = image(&[(0, 0, &[200]), (0, 0, &[67, 6, 0])], &[], &[]);
        let mut regs = Regs::default();
        assert!(matches!(run(&img, 0, &mut [], &mut regs), Err(Error::Opcode { at: 6, op: 200, .. })));
        // A jump to itself never ends.
        assert!(matches!(run(&img, 1, &mut [], &mut regs), Err(Error::Stuck { .. })));
        assert_eq!(run(&img, 9, &mut [], &mut regs), Err(Error::NoTable(9)));
    }

    /// Every command table of the reference PC's VBIOS, run against registers that
    /// read 0: none may stop on an opcode the interpreter doesn't know
    /// (tables waiting for hardware that never answers count as stuck).
    #[test]
    fn refpc_tables() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/vbios.rom");
        let Ok(d) = std::fs::read(path) else { return };
        let rom = crate::atom::Rom::new(&d).unwrap();
        let mut i = Interp::new(&rom, 4096);
        let (mut ran, mut stuck) = (0, 0);
        for t in 0..=255u8 {
            if !i.has(t) {
                continue;
            }
            let mut ps = [0u32; 64];
            let mut regs = Regs::default();
            match i.execute(&mut regs, t, &mut ps) {
                Ok(()) => ran += 1,
                Err(Error::Stuck { .. }) | Err(Error::Io) => stuck += 1,
                Err(e) => panic!("table {t}: {e:?}"),
            }
        }
        std::println!("the reference PC's VBIOS: {ran} tables ran to their end, {stuck} waited on hardware");
        // Raphael's VBIOS has eight command tables (asic_init,
        // enabledisppowergating, getsmuclockinfo and five unnamed ones):
        // all decode; only one waits on hardware here.
        assert_eq!(ran + stuck, 8);
        assert!(ran >= 7);
    }
}
