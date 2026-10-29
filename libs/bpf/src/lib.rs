// SPDX-License-Identifier: MIT OR Apache-2.0

//! BPF interpreters (ADR 0028).
//!
//! [`run_ebpf`] runs an eBPF program, following the instruction set as
//! RFC 9669 ("BPF Instruction Set Architecture") specifies it, with a
//! read-only context and a 512-byte stack. There is no verifier: every
//! memory access is checked as it happens, the number of steps is bounded,
//! and helper calls are refused. The kernel uses it for cgroup device
//! programs.
//!
//! [`check_cbpf`] and [`run_cbpf`] are classic BPF, as seccomp(2) uses it:
//! a filter of `struct sock_filter` instructions reads a fixed-size data
//! block (`struct seccomp_data`) and returns a 32-bit action. The opcode
//! layout is the one bpf(4) on the BSDs and seccomp(2) describe; checking
//! first (jumps only forward, loads aligned and inside the data, a return
//! at the end) means running can't fail.
//!
//! [`check_socket_filter`] and [`run_socket_filter`] are classic BPF on
//! packets, as socket(7)'s SO_ATTACH_FILTER uses it (bpf(4)): word, half
//! word and byte loads in network byte order, at a fixed offset or X plus
//! one, the packet's length, and `4 * (P[k] & 0xf)` into X (an IP header's
//! length). A load past the packet's end ends the filter with 0 (drop);
//! the result is how many bytes of the packet to keep.

#![no_std]

#[cfg(test)]
extern crate std;

/// Why a program could not run to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An instruction this interpreter doesn't know (or a helper call).
    BadInstruction(usize),
    /// A load or store outside the context or the stack.
    BadAccess(usize),
    /// A jump outside the program.
    BadJump(usize),
    /// More steps than [`MAX_STEPS`].
    TooLong,
}

/// The stack each program gets (RFC 9669 §2.3: 512 bytes, R10 at its end).
pub const STACK_SIZE: usize = 512;
/// The most instructions one run executes.
pub const MAX_STEPS: usize = 1 << 20;

// Where the context and the stack appear to the program.
const CTX_BASE: u64 = 0x1000_0000;
const STACK_BASE: u64 = 0x2000_0000;

// Instruction classes, sizes, modes, operations (RFC 9669 §3, §4, §5).
const CLASS_LD: u8 = 0x00;
const CLASS_LDX: u8 = 0x01;
const CLASS_ST: u8 = 0x02;
const CLASS_STX: u8 = 0x03;
const CLASS_ALU: u8 = 0x04;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const CLASS_ALU64: u8 = 0x07;
const MODE_IMM: u8 = 0x00;
const MODE_MEM: u8 = 0x60;
const SRC_X: u8 = 0x08;

/// One decoded instruction (RFC 9669 §3.1, little-endian encoding).
#[derive(Clone, Copy, Debug)]
struct Insn {
    op: u8,
    dst: usize,
    src: usize,
    off: i16,
    imm: i32,
}

fn decode(raw: u64) -> Insn {
    let b = raw.to_le_bytes();
    Insn {
        op: b[0],
        dst: usize::from(b[1] & 0x0F),
        src: usize::from(b[1] >> 4),
        off: i16::from_le_bytes([b[2], b[3]]),
        imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    }
}

/// Encode an instruction (for tests and for programs the kernel builds).
pub const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    let o = off.to_le_bytes();
    let i = imm.to_le_bytes();
    u64::from_le_bytes([op, (dst & 0x0F) | (src << 4), o[0], o[1], i[0], i[1], i[2], i[3]])
}

struct Memory<'a> {
    ctx: &'a [u8],
    stack: [u8; STACK_SIZE],
}

impl Memory<'_> {
    fn load(&self, addr: u64, size: usize, pc: usize) -> Result<u64, Error> {
        let (region, base): (&[u8], u64) =
            if addr >= STACK_BASE { (&self.stack, STACK_BASE) } else { (self.ctx, CTX_BASE) };
        let off = addr.checked_sub(base).ok_or(Error::BadAccess(pc))? as usize;
        let bytes = region.get(off..off.checked_add(size).ok_or(Error::BadAccess(pc))?).ok_or(Error::BadAccess(pc))?;
        let mut v = [0u8; 8];
        v[..size].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(v))
    }

    /// Only the stack is writable.
    fn store(&mut self, addr: u64, size: usize, value: u64, pc: usize) -> Result<(), Error> {
        let off = addr.checked_sub(STACK_BASE).ok_or(Error::BadAccess(pc))? as usize;
        let end = off.checked_add(size).ok_or(Error::BadAccess(pc))?;
        let slot = self.stack.get_mut(off..end).ok_or(Error::BadAccess(pc))?;
        slot.copy_from_slice(&value.to_le_bytes()[..size]);
        Ok(())
    }
}

fn size_of(op: u8) -> usize {
    match op & 0x18 {
        0x00 => 4,
        0x08 => 2,
        0x10 => 1,
        _ => 8,
    }
}

/// An arithmetic operation (RFC 9669 §4.1). `None` for an unknown one.
/// Division by zero gives 0, and modulo by zero leaves `dst`, as §4.1 says.
fn alu(op: u8, dst: u64, src: u64, wide: bool) -> Option<u64> {
    let mask = if wide { 63 } else { 31 };
    let r = match op & 0xF0 {
        0x00 => dst.wrapping_add(src),
        0x10 => dst.wrapping_sub(src),
        0x20 => dst.wrapping_mul(src),
        0x30 => {
            if wide {
                dst.checked_div(src).unwrap_or(0)
            } else {
                u64::from((dst as u32).checked_div(src as u32).unwrap_or(0))
            }
        }
        0x40 => dst | src,
        0x50 => dst & src,
        0x60 => dst.wrapping_shl((src & mask) as u32),
        0x70 => {
            if wide {
                dst.wrapping_shr((src & mask) as u32)
            } else {
                u64::from((dst as u32).wrapping_shr((src & mask) as u32))
            }
        }
        0x80 => dst.wrapping_neg(),
        0x90 => {
            if wide {
                dst.checked_rem(src).unwrap_or(dst)
            } else {
                u64::from((dst as u32).checked_rem(src as u32).unwrap_or(dst as u32))
            }
        }
        0xA0 => dst ^ src,
        0xB0 => src,
        0xC0 => {
            if wide {
                ((dst as i64) >> (src & mask)) as u64
            } else {
                u64::from(((dst as i32) >> (src & mask)) as u32)
            }
        }
        _ => return None,
    };
    Some(if wide { r } else { r & 0xFFFF_FFFF })
}

/// Whether a conditional jump is taken (RFC 9669 §4.3).
fn condition(op: u8, a: u64, b: u64, wide: bool) -> Option<bool> {
    let (a, b) = if wide { (a, b) } else { (a & 0xFFFF_FFFF, b & 0xFFFF_FFFF) };
    let (sa, sb) = if wide { (a as i64, b as i64) } else { (i64::from(a as i32), i64::from(b as i32)) };
    Some(match op & 0xF0 {
        0x10 => a == b,
        0x20 => a > b,
        0x30 => a >= b,
        0x40 => a & b != 0,
        0x50 => a != b,
        0x60 => sa > sb,
        0x70 => sa >= sb,
        0xA0 => a < b,
        0xB0 => a <= b,
        0xC0 => sa < sb,
        0xD0 => sa <= sb,
        _ => return None,
    })
}

/// Run `prog` with R1 pointing at `ctx`; returns R0 at exit.
pub fn run_ebpf(prog: &[u64], ctx: &[u8]) -> Result<u64, Error> {
    let mut r = [0u64; 11];
    r[1] = CTX_BASE;
    r[10] = STACK_BASE + STACK_SIZE as u64;
    let mut mem = Memory { ctx, stack: [0; STACK_SIZE] };
    let mut pc = 0usize;
    for _ in 0..MAX_STEPS {
        let raw = *prog.get(pc).ok_or(Error::BadJump(pc))?;
        let i = decode(raw);
        if i.dst > 10 || i.src > 10 {
            return Err(Error::BadInstruction(pc));
        }
        let class = i.op & 0x07;
        let imm = i64::from(i.imm) as u64;
        let mut next = pc + 1;
        match class {
            CLASS_ALU | CLASS_ALU64 => {
                let wide = class == CLASS_ALU64;
                if i.dst == 10 {
                    return Err(Error::BadInstruction(pc)); // R10 is read-only.
                }
                if i.op & 0xF0 == 0xD0 {
                    // Byte swaps (§4.2): imm is the width. ALU64 always
                    // swaps; in ALU, TO_BE swaps and TO_LE truncates (on a
                    // little-endian machine).
                    let v = r[i.dst];
                    let swap = wide || i.op & SRC_X != 0;
                    r[i.dst] = match (i.imm, swap) {
                        (16, true) => u64::from((v as u16).swap_bytes()),
                        (32, true) => u64::from((v as u32).swap_bytes()),
                        (64, true) => v.swap_bytes(),
                        (16, false) => v & 0xFFFF,
                        (32, false) => v & 0xFFFF_FFFF,
                        (64, false) => v,
                        _ => return Err(Error::BadInstruction(pc)),
                    };
                } else {
                    let src = if i.op & SRC_X != 0 {
                        r[i.src]
                    } else if wide {
                        imm
                    } else {
                        imm & 0xFFFF_FFFF
                    };
                    r[i.dst] = alu(i.op, r[i.dst], src, wide).ok_or(Error::BadInstruction(pc))?;
                }
            }
            CLASS_JMP | CLASS_JMP32 => {
                let wide = class == CLASS_JMP;
                match i.op & 0xF0 {
                    0x90 if wide => return Ok(r[0]),               // EXIT
                    0x80 => return Err(Error::BadInstruction(pc)), // CALL: no helpers
                    0x00 => {
                        // JA (JMP32's uses imm as the offset).
                        let off = if wide { i64::from(i.off) } else { i64::from(i.imm) };
                        next = (pc as i64 + 1 + off).try_into().map_err(|_| Error::BadJump(pc))?;
                    }
                    _ => {
                        let src = if i.op & SRC_X != 0 { r[i.src] } else { imm };
                        if condition(i.op, r[i.dst], src, wide).ok_or(Error::BadInstruction(pc))? {
                            next = (pc as i64 + 1 + i64::from(i.off)).try_into().map_err(|_| Error::BadJump(pc))?;
                        }
                    }
                }
            }
            CLASS_LDX if i.op & 0xE0 == MODE_MEM => {
                let addr = r[i.src].wrapping_add(i64::from(i.off) as u64);
                r[i.dst] = mem.load(addr, size_of(i.op), pc)?;
            }
            CLASS_ST if i.op & 0xE0 == MODE_MEM => {
                let addr = r[i.dst].wrapping_add(i64::from(i.off) as u64);
                mem.store(addr, size_of(i.op), imm, pc)?;
            }
            CLASS_STX if i.op & 0xE0 == MODE_MEM => {
                let addr = r[i.dst].wrapping_add(i64::from(i.off) as u64);
                mem.store(addr, size_of(i.op), r[i.src], pc)?;
            }
            // 64-bit immediate load: two slots (§5.4), plain immediates only.
            CLASS_LD if i.op == (CLASS_LD | MODE_IMM | 0x18) && i.src == 0 => {
                let hi = decode(*prog.get(pc + 1).ok_or(Error::BadInstruction(pc))?).imm;
                r[i.dst] = u64::from(i.imm as u32) | (u64::from(hi as u32) << 32);
                next = pc + 2;
            }
            _ => return Err(Error::BadInstruction(pc)),
        }
        pc = next;
    }
    Err(Error::TooLong)
}

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    /// From the 8 bytes of a `struct sock_filter` (native byte order).
    pub fn from_bytes(b: [u8; 8]) -> SockFilter {
        SockFilter {
            code: u16::from_ne_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// BPF_MAXINSNS: the longest classic filter.
pub const CBPF_MAX_INSNS: usize = 4096;
/// Scratch memory words (BPF_MEMWORDS).
const MEMWORDS: usize = 16;

// Classic BPF fields (bpf(4)): class, size, mode, ALU/JMP operation,
// source, RET source, MISC operation.
const C_LD: u16 = 0x00;
const C_LDX: u16 = 0x01;
const C_ST: u16 = 0x02;
const C_STX: u16 = 0x03;
const C_ALU: u16 = 0x04;
const C_JMP: u16 = 0x05;
const C_RET: u16 = 0x06;
const C_MISC: u16 = 0x07;
const S_W: u16 = 0x00;
const M_IMM: u16 = 0x00;
const M_ABS: u16 = 0x20;
const M_IND: u16 = 0x40;
const M_MEM: u16 = 0x60;
const M_LEN: u16 = 0x80;
const M_MSH: u16 = 0xA0;
const S_H: u16 = 0x08;
const S_B: u16 = 0x10;
const SRC_K: u16 = 0x00;
const RVAL_A: u16 = 0x10;

/// Why a classic filter is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CbpfError {
    /// Empty or longer than [`CBPF_MAX_INSNS`].
    Length,
    /// Instruction `n` is not allowed (unknown, a load outside the data or
    /// unaligned, a jump out of the filter, scratch memory out of range,
    /// division by a constant zero).
    Insn(usize),
    /// The last instruction isn't a return.
    NoReturn,
}

/// Check a classic filter that reads `data_len` bytes of data in 32-bit
/// words (seccomp's rules: only word loads at aligned offsets).
pub fn check_cbpf(prog: &[SockFilter], data_len: usize) -> Result<(), CbpfError> {
    if prog.is_empty() || prog.len() > CBPF_MAX_INSNS {
        return Err(CbpfError::Length);
    }
    for (pc, i) in prog.iter().enumerate() {
        let k = i.k as usize;
        let ok = match i.code & 0x07 {
            C_LD | C_LDX => match i.code & 0xE0 {
                M_ABS => i.code & 0x07 == C_LD && i.code & 0x18 == S_W && k % 4 == 0 && k + 4 <= data_len,
                M_IMM | M_LEN => i.code & 0x18 == S_W,
                M_MEM => i.code & 0x18 == S_W && k < MEMWORDS,
                _ => false,
            },
            C_ST | C_STX => k < MEMWORDS,
            C_ALU => match i.code & 0xF0 {
                0x30 | 0x90 => i.code & 0x08 != SRC_K || i.k != 0, // DIV, MOD
                0x00 | 0x10 | 0x20 | 0x40 | 0x50 | 0x60 | 0x70 | 0x80 | 0xA0 => true,
                _ => false,
            },
            C_JMP => match i.code & 0xF0 {
                0x00 => pc + 1 + k < prog.len(),
                0x10..=0x40 => pc + 1 + usize::from(i.jt.max(i.jf)) < prog.len(),
                _ => false,
            },
            C_RET => matches!(i.code & 0x18, 0x00 | RVAL_A),
            C_MISC => matches!(i.code & 0xF8, 0x00 | 0x80), // TAX, TXA
            _ => false,
        };
        if !ok {
            return Err(CbpfError::Insn(pc));
        }
    }
    if prog[prog.len() - 1].code & 0x07 != C_RET {
        return Err(CbpfError::NoReturn);
    }
    Ok(())
}

/// Check a socket filter (packets of any length, so loads are checked
/// when they run).
pub fn check_socket_filter(prog: &[SockFilter]) -> Result<(), CbpfError> {
    if prog.is_empty() || prog.len() > CBPF_MAX_INSNS {
        return Err(CbpfError::Length);
    }
    for (pc, i) in prog.iter().enumerate() {
        let k = i.k as usize;
        let size_ok = matches!(i.code & 0x18, S_W | S_H | S_B);
        let ok = match i.code & 0x07 {
            C_LD => match i.code & 0xE0 {
                M_ABS | M_IND => size_ok,
                M_IMM | M_LEN => i.code & 0x18 == S_W,
                M_MEM => i.code & 0x18 == S_W && k < MEMWORDS,
                _ => false,
            },
            C_LDX => match i.code & 0xE0 {
                M_IMM | M_LEN => i.code & 0x18 == S_W,
                M_MEM => i.code & 0x18 == S_W && k < MEMWORDS,
                M_MSH => i.code & 0x18 == S_B,
                _ => false,
            },
            C_ST | C_STX => k < MEMWORDS,
            C_ALU => match i.code & 0xF0 {
                0x30 | 0x90 => i.code & 0x08 != SRC_K || i.k != 0,
                0x00 | 0x10 | 0x20 | 0x40 | 0x50 | 0x60 | 0x70 | 0x80 | 0xA0 => true,
                _ => false,
            },
            C_JMP => match i.code & 0xF0 {
                0x00 => pc + 1 + k < prog.len(),
                0x10..=0x40 => pc + 1 + usize::from(i.jt.max(i.jf)) < prog.len(),
                _ => false,
            },
            C_RET => matches!(i.code & 0x18, 0x00 | RVAL_A),
            C_MISC => matches!(i.code & 0xF8, 0x00 | 0x80),
            _ => false,
        };
        if !ok {
            return Err(CbpfError::Insn(pc));
        }
    }
    if prog[prog.len() - 1].code & 0x07 != C_RET {
        return Err(CbpfError::NoReturn);
    }
    Ok(())
}

/// Run a filter that [`check_socket_filter`] accepted on `packet`: how many
/// of its bytes to keep (0: drop it).
pub fn run_socket_filter(prog: &[SockFilter], packet: &[u8]) -> u32 {
    run(prog, packet, true)
}

/// Run a filter that [`check_cbpf`] accepted for `data` (word loads read
/// native byte order, as seccomp_data's fields are host values).
pub fn run_cbpf(prog: &[SockFilter], data: &[u8]) -> u32 {
    run(prog, data, false)
}

/// A packet load of `size` bytes at `at`, big-endian (None: past the end).
fn load(packet: &[u8], at: u64, size: u16) -> Option<u32> {
    let n = match size {
        S_W => 4,
        S_H => 2,
        _ => 1,
    };
    let at = usize::try_from(at).ok()?;
    let b = packet.get(at..at.checked_add(n)?)?;
    Some(b.iter().fold(0u32, |v, &x| (v << 8) | u32::from(x)))
}

fn run(prog: &[SockFilter], data: &[u8], packet: bool) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; MEMWORDS];
    let mut pc = 0;
    loop {
        let Some(i) = prog.get(pc) else { return 0 };
        let k = i.k;
        pc += 1;
        match i.code & 0x07 {
            C_LD | C_LDX if packet && matches!(i.code & 0xE0, M_ABS | M_IND | M_MSH) => {
                let mode = i.code & 0xE0;
                let at = u64::from(k) + if mode == M_IND { u64::from(x) } else { 0 };
                let Some(v) = load(data, at, i.code & 0x18) else { return 0 };
                match (i.code & 0x07, mode) {
                    (C_LDX, _) => x = 4 * (v & 0xF),
                    _ => a = v,
                }
            }
            C_LD | C_LDX => {
                let v = match i.code & 0xE0 {
                    M_ABS => {
                        let o = k as usize;
                        data.get(o..o + 4).map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                    }
                    M_IMM => k,
                    M_LEN => data.len() as u32,
                    _ => mem[k as usize % MEMWORDS],
                };
                if i.code & 0x07 == C_LD {
                    a = v;
                } else {
                    x = v;
                }
            }
            C_ST => mem[k as usize % MEMWORDS] = a,
            C_STX => mem[k as usize % MEMWORDS] = x,
            C_ALU => {
                let src = if i.code & 0x08 == SRC_K { k } else { x };
                a = match i.code & 0xF0 {
                    0x00 => a.wrapping_add(src),
                    0x10 => a.wrapping_sub(src),
                    0x20 => a.wrapping_mul(src),
                    0x30 => a.checked_div(src).unwrap_or(0),
                    0x40 => a | src,
                    0x50 => a & src,
                    0x60 => a.checked_shl(src).unwrap_or(0),
                    0x70 => a.checked_shr(src).unwrap_or(0),
                    0x80 => a.wrapping_neg(),
                    0x90 => a.checked_rem(src).unwrap_or(0),
                    _ => a ^ src,
                };
            }
            C_JMP => {
                let src = if i.code & 0x08 == SRC_K { k } else { x };
                let taken = match i.code & 0xF0 {
                    0x00 => {
                        pc += k as usize;
                        continue;
                    }
                    0x10 => a == src,
                    0x20 => a > src,
                    0x30 => a >= src,
                    _ => a & src != 0,
                };
                pc += usize::from(if taken { i.jt } else { i.jf });
            }
            C_RET => return if i.code & 0x18 == RVAL_A { a } else { k },
            _ => {
                if i.code & 0xF8 == 0x80 {
                    a = x; // TXA
                } else {
                    x = a; // TAX
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_filter_on_a_frame() {
        // Keep IPv4 UDP datagrams to port 68 (as a DHCP client's filter
        // does), dropping everything else: ethertype at 12, protocol at
        // 23, the IP header's length from byte 14, the port after it.
        let prog = [
            f(C_LD | S_H | M_ABS, 0, 0, 12),
            f(C_JMP | 0x10, 0, 6, 0x0800),
            f(C_LD | S_B | M_ABS, 0, 0, 23),
            f(C_JMP | 0x10, 0, 4, 17),
            f(C_LDX | S_B | M_MSH, 0, 0, 14),
            f(C_LD | S_H | M_IND, 0, 0, 16),
            f(C_JMP | 0x10, 0, 1, 68),
            f(C_RET, 0, 0, 0xFFFF),
            f(C_RET, 0, 0, 0),
        ];
        assert_eq!(check_socket_filter(&prog), Ok(()));
        let mut frame = std::vec![0u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[23] = 17;
        frame[36..38].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(run_socket_filter(&prog, &frame), 0xFFFF);
        frame[37] = 67;
        assert_eq!(run_socket_filter(&prog, &frame), 0);
        // A frame too short for a load is dropped.
        assert_eq!(run_socket_filter(&prog, &frame[..20]), 0);
        // Loads the seccomp checker refuses are fine here, and odd modes are not.
        assert!(check_cbpf(&prog, 64).is_err());
        assert_eq!(check_socket_filter(&[f(C_LDX | S_W | M_MSH, 0, 0, 0), f(C_RET, 0, 0, 0)]), Err(CbpfError::Insn(0)));
    }

    // Opcodes used below.
    const MOV64_K: u8 = CLASS_ALU64 | 0xB0;
    const MOV64_X: u8 = CLASS_ALU64 | 0xB0 | SRC_X;
    const ADD64_K: u8 = CLASS_ALU64;
    const AND32_K: u8 = CLASS_ALU | 0x50;
    const RSH32_K: u8 = CLASS_ALU | 0x70;
    const DIV64_X: u8 = CLASS_ALU64 | 0x30 | SRC_X;
    const LDX_W: u8 = CLASS_LDX | MODE_MEM;
    const STX_DW: u8 = CLASS_STX | MODE_MEM | 0x18;
    const LDX_DW: u8 = CLASS_LDX | MODE_MEM | 0x18;
    const JEQ_K: u8 = CLASS_JMP | 0x10;
    const JNE32_K: u8 = CLASS_JMP32 | 0x50;
    const JA: u8 = CLASS_JMP;
    const EXIT: u8 = CLASS_JMP | 0x90;

    #[test]
    fn returns_r0() {
        let p = [insn(MOV64_K, 0, 0, 0, 42), insn(EXIT, 0, 0, 0, 0)];
        assert_eq!(run_ebpf(&p, &[]), Ok(42));
    }

    /// The shape of a cgroup device program: allow char device 1:3 for
    /// read, deny everything else. Context: access_type (type | access <<
    /// 16), major, minor.
    fn device_prog() -> [u64; 12] {
        [
            insn(LDX_W, 2, 1, 0, 0), // r2 = access_type
            insn(MOV64_X, 3, 2, 0, 0),
            insn(AND32_K, 2, 0, 0, 0xFFFF), // r2 = device type
            insn(RSH32_K, 3, 0, 0, 16),     // r3 = access
            insn(LDX_W, 4, 1, 4, 0),        // r4 = major
            insn(LDX_W, 5, 1, 8, 0),        // r5 = minor
            insn(JNE32_K, 2, 0, 4, 2),      // not a char device: deny
            insn(JNE32_K, 4, 0, 3, 1),      // major != 1: deny
            insn(JNE32_K, 5, 0, 2, 3),      // minor != 3: deny
            insn(MOV64_K, 0, 0, 0, 1),
            insn(EXIT, 0, 0, 0, 0),
            insn(MOV64_K, 0, 0, 0, 0), // unreachable here; deny path below
        ]
    }

    fn ctx(kind: u32, access: u32, major: u32, minor: u32) -> [u8; 12] {
        let mut c = [0u8; 12];
        c[..4].copy_from_slice(&(kind | (access << 16)).to_le_bytes());
        c[4..8].copy_from_slice(&major.to_le_bytes());
        c[8..].copy_from_slice(&minor.to_le_bytes());
        c
    }

    #[test]
    fn device_program() {
        let mut p = device_prog().to_vec();
        p.push(insn(EXIT, 0, 0, 0, 0));
        assert_eq!(run_ebpf(&p, &ctx(2, 2, 1, 3)), Ok(1));
        assert_eq!(run_ebpf(&p, &ctx(2, 2, 1, 5)), Ok(0));
        assert_eq!(run_ebpf(&p, &ctx(1, 2, 1, 3)), Ok(0));
    }

    #[test]
    fn stack_round_trip_and_division_by_zero() {
        let p = [
            insn(MOV64_K, 1, 0, 0, 7),
            insn(STX_DW, 10, 1, -8, 0),
            insn(LDX_DW, 0, 10, -8, 0),
            insn(MOV64_K, 2, 0, 0, 0),
            insn(DIV64_X, 1, 2, 0, 0), // 7 / 0 = 0
            insn(ADD64_K, 0, 0, 0, 1),
            insn(JEQ_K, 1, 0, 1, 0), // r1 == 0: skip the next
            insn(MOV64_K, 0, 0, 0, 99),
            insn(EXIT, 0, 0, 0, 0),
        ];
        assert_eq!(run_ebpf(&p, &[]), Ok(8));
    }

    #[test]
    fn faults_are_errors() {
        // Writing the context, reading past it, jumping out, looping.
        let write_ctx = [insn(STX_DW, 1, 0, 0, 0), insn(EXIT, 0, 0, 0, 0)];
        assert_eq!(run_ebpf(&write_ctx, &[0; 8]), Err(Error::BadAccess(0)));
        let read_past = [insn(LDX_W, 0, 1, 8, 0), insn(EXIT, 0, 0, 0, 0)];
        assert_eq!(run_ebpf(&read_past, &[0; 8]), Err(Error::BadAccess(0)));
        let jump_out = [insn(JA, 0, 0, 5, 0)];
        assert_eq!(run_ebpf(&jump_out, &[]), Err(Error::BadJump(6)));
        let forever = [insn(JA, 0, 0, -1, 0)];
        assert_eq!(run_ebpf(&forever, &[]), Err(Error::TooLong));
        let call = [insn(CLASS_JMP | 0x80, 0, 0, 0, 1), insn(EXIT, 0, 0, 0, 0)];
        assert_eq!(run_ebpf(&call, &[]), Err(Error::BadInstruction(0)));
    }

    #[test]
    fn byte_swaps() {
        let run = |op: u8, width: i32| {
            let p = [
                insn(CLASS_LD | 0x18, 0, 0, 0, 0x0506_0708),
                insn(0, 0, 0, 0, 0x0102_0304),
                insn(op, 0, 0, 0, width),
                insn(EXIT, 0, 0, 0, 0),
            ];
            run_ebpf(&p, &[])
        };
        assert_eq!(run(CLASS_ALU | 0xD0 | SRC_X, 16), Ok(0x0807)); // TO_BE
        assert_eq!(run(CLASS_ALU | 0xD0, 32), Ok(0x0506_0708)); // TO_LE
        assert_eq!(run(CLASS_ALU64 | 0xD0, 64), Ok(0x0807_0605_0403_0201));
    }

    fn f(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// A typical seccomp filter: check the architecture, kill on a wrong
    /// one, fail `getpid` (39) with EPERM, allow the rest.
    fn seccomp_filter() -> [SockFilter; 7] {
        [
            f(C_LD | S_W | M_ABS, 0, 0, 4),     // A = arch
            f(C_JMP | 0x10, 1, 0, 0xC000_003E), // == x86-64?
            f(C_RET, 0, 0, 0),                  // KILL_THREAD
            f(C_LD | S_W | M_ABS, 0, 0, 0),     // A = nr
            f(C_JMP | 0x10, 0, 1, 39),          // == getpid?
            f(C_RET, 0, 0, 0x0005_0000 | 1),    // ERRNO(EPERM)
            f(C_RET, 0, 0, 0x7FFF_0000),        // ALLOW
        ]
    }

    fn data(nr: u32, arch: u32) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[..4].copy_from_slice(&nr.to_ne_bytes());
        d[4..8].copy_from_slice(&arch.to_ne_bytes());
        d
    }

    #[test]
    fn seccomp_style_filter() {
        let p = seccomp_filter();
        assert_eq!(check_cbpf(&p, 64), Ok(()));
        assert_eq!(run_cbpf(&p, &data(39, 0xC000_003E)), 0x0005_0001);
        assert_eq!(run_cbpf(&p, &data(1, 0xC000_003E)), 0x7FFF_0000);
        assert_eq!(run_cbpf(&p, &data(39, 0x4000_0003)), 0);
    }

    #[test]
    fn cbpf_checks() {
        assert_eq!(check_cbpf(&[], 64), Err(CbpfError::Length));
        // Unaligned, past the end, a jump out, no return at the end.
        assert_eq!(check_cbpf(&[f(C_LD | S_W | M_ABS, 0, 0, 2), f(C_RET, 0, 0, 0)], 64), Err(CbpfError::Insn(0)));
        assert_eq!(check_cbpf(&[f(C_LD | S_W | M_ABS, 0, 0, 64), f(C_RET, 0, 0, 0)], 64), Err(CbpfError::Insn(0)));
        assert_eq!(check_cbpf(&[f(C_JMP | 0x10, 5, 0, 0), f(C_RET, 0, 0, 0)], 64), Err(CbpfError::Insn(0)));
        assert_eq!(check_cbpf(&[f(C_LD | M_IMM, 0, 0, 1)], 64), Err(CbpfError::NoReturn));
        assert_eq!(check_cbpf(&[f(C_ALU | 0x30, 0, 0, 0), f(C_RET, 0, 0, 0)], 64), Err(CbpfError::Insn(0)));
    }

    #[test]
    fn cbpf_scratch_alu_and_return_a() {
        let p = [
            f(C_LD | M_IMM, 0, 0, 6),
            f(C_ST, 0, 0, 3),
            f(C_LDX | M_MEM, 0, 0, 3),       // X = 6
            f(C_ALU | 0x20 | 0x08, 0, 0, 0), // A *= X
            f(C_ALU, 0, 0, 6),               // A += 6 (BPF_ADD is 0)
            f(C_MISC, 0, 0, 0),              // X = A (TAX)
            f(C_LD | M_LEN, 0, 0, 0),        // A = len
            f(C_MISC | 0x80, 0, 0, 0),       // A = X (TXA)
            f(C_RET | RVAL_A, 0, 0, 0),
        ];
        assert_eq!(check_cbpf(&p, 64), Ok(()));
        assert_eq!(run_cbpf(&p, &[0; 64]), 42);
    }

    #[test]
    fn imm64_and_alu32_truncation() {
        let p = [
            insn(CLASS_LD | 0x18, 0, 0, 0, 0x5555_5555),
            insn(0, 0, 0, 0, 0x1),
            insn(CLASS_ALU, 0, 0, 0, 1), // 32-bit add (BPF_ADD is 0) zero-extends
            insn(EXIT, 0, 0, 0, 0),
        ];
        assert_eq!(run_ebpf(&p, &[]), Ok(0x5555_5556));
    }
}
