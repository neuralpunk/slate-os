// SPDX-License-Identifier: MIT OR Apache-2.0

//! A host-side interpreter of exactly the RDNA 2 instructions Slate's
//! shaders use (ADR 0172), to test them before a GPU runs them: wave32,
//! each lane in turn, memory a map of dwords. It decodes the dwords the
//! encoder made (so the encodings are checked too) and refuses anything
//! it doesn't know. Semantics from AMD's RDNA 2 Shader ISA guide (each
//! instruction's description; docs/gpu/SOURCES.md).

use std::collections::HashMap;
use std::vec::Vec;

use crate::rdna2::op;

/// A dispatch: the program, its user SGPRs, threads a group (X only) and
/// groups (X and Y), whether the group's Y ID follows the X one.
pub struct Dispatch<'a> {
    pub program: &'a [u32],
    pub user: &'a [u32],
    pub threads: u32,
    pub groups: (u32, u32),
    pub tgid_y: bool,
}

pub struct Wave {
    s: [u32; 128],
    v: Vec<[u32; 32]>,
    scc: bool,
}

impl Wave {
    fn exec(&self) -> u32 {
        self.s[126]
    }

    /// A 9-bit source operand for `lane`; `literal` the dword after the
    /// instruction.
    fn src(&self, code: u32, lane: usize, literal: u32) -> u32 {
        match code {
            0..=127 => self.s[code as usize],
            128..=192 => code - 128,
            193..=208 => (-((code - 192) as i32)) as u32,
            240 => 0.5f32.to_bits(),
            241 => (-0.5f32).to_bits(),
            242 => 1.0f32.to_bits(),
            243 => (-1.0f32).to_bits(),
            244 => 2.0f32.to_bits(),
            245 => (-2.0f32).to_bits(),
            246 => 4.0f32.to_bits(),
            247 => (-4.0f32).to_bits(),
            255 => literal,
            256..=511 => self.v[(code - 256) as usize][lane],
            _ => panic!("source operand {code} not known to the interpreter"),
        }
    }
}

fn f(x: u32) -> f32 {
    f32::from_bits(x)
}

/// Run `d` over `mem` (byte addresses, dword aligned).
pub fn run(d: &Dispatch<'_>, mem: &mut HashMap<u64, u32>) {
    for gy in 0..d.groups.1 {
        for gx in 0..d.groups.0 {
            for wave in 0..d.threads.div_ceil(32) {
                let mut w = Wave { s: [0; 128], v: std::vec![[0; 32]; 256], scc: false };
                w.s[..d.user.len()].copy_from_slice(d.user);
                let n = d.user.len();
                w.s[n] = gx;
                if d.tgid_y {
                    w.s[n + 1] = gy;
                }
                let lanes = (d.threads - wave * 32).min(32);
                w.s[126] = if lanes == 32 { u32::MAX } else { (1 << lanes) - 1 };
                for (lane, id) in w.v[0].iter_mut().enumerate() {
                    *id = wave * 32 + lane as u32;
                }
                wave_run(&mut w, d.program, mem);
            }
        }
    }
}

fn wave_run(w: &mut Wave, prog: &[u32], mem: &mut HashMap<u64, u32>) {
    let mut pc = 0usize;
    for _ in 0..1_000_000 {
        let i = prog[pc];
        let next = |k: usize| prog.get(pc + k).copied().unwrap_or(0);
        if i >> 23 == 0x17F {
            // SOPP.
            let (o, simm) = ((i >> 16) & 0x7F, (i & 0xFFFF) as i16);
            let jump = |pc: usize| (pc as i64 + 1 + i64::from(simm)) as usize;
            pc = match o {
                op::S_ENDPGM => return,
                op::S_WAITCNT => pc + 1,
                op::S_BRANCH => jump(pc),
                op::S_CBRANCH_SCC1 if w.scc => jump(pc),
                op::S_CBRANCH_EXECZ if w.exec() == 0 => jump(pc),
                op::S_CBRANCH_SCC1 | op::S_CBRANCH_EXECZ => pc + 1,
                _ => panic!("SOPP {o} at {pc}"),
            };
        } else if i >> 23 == 0x17E {
            // SOPC.
            let (o, a, b) = ((i >> 16) & 0x7F, i & 0xFF, (i >> 8) & 0xFF);
            let lit = next(1);
            let (x, y) = (w.src(a, 0, lit), w.src(b, 0, lit));
            w.scc = match o {
                op::S_CMP_LT_U32 => x < y,
                _ => panic!("SOPC {o}"),
            };
            pc += 1 + usize::from(a == 255 || b == 255);
        } else if i >> 23 == 0x17D {
            // SOP1.
            let (sdst, o, a) = (((i >> 16) & 0x7F) as usize, (i >> 8) & 0xFF, i & 0xFF);
            let x = w.src(a, 0, next(1));
            match o {
                op::S_MOV_B32 => w.s[sdst] = x,
                op::S_AND_SAVEEXEC_B32 => {
                    w.s[sdst] = w.s[126];
                    w.s[126] &= x;
                    w.scc = w.s[126] != 0;
                }
                _ => panic!("SOP1 {o}"),
            }
            pc += 1 + usize::from(a == 255);
        } else if i >> 28 == 0xB {
            // SOPK.
            match (i >> 23) & 0x1F {
                op::S_WAITCNT_VSCNT => pc += 1,
                o => panic!("SOPK {o}"),
            }
        } else if i >> 30 == 2 {
            // SOP2.
            let (o, sdst, a, b) = ((i >> 23) & 0x7F, ((i >> 16) & 0x7F) as usize, i & 0xFF, (i >> 8) & 0xFF);
            let lit = next(1);
            let (x, y) = (w.src(a, 0, lit), w.src(b, 0, lit));
            match o {
                op::S_ADD_U32 => {
                    let (r, c) = x.overflowing_add(y);
                    w.s[sdst] = r;
                    w.scc = c;
                }
                _ => panic!("SOP2 {o}"),
            }
            pc += 1 + usize::from(a == 255 || b == 255);
        } else if i >> 25 == 0x3F {
            // VOP1.
            let (vdst, o, a) = (((i >> 17) & 0xFF) as usize, (i >> 9) & 0xFF, i & 0x1FF);
            let lit = next(1);
            for lane in lanes(w) {
                let x = w.src(a, lane, lit);
                w.v[vdst][lane] = match o {
                    op::V_MOV_B32 => x,
                    op::V_CVT_F32_U32 => (x as f32).to_bits(),
                    op::V_CVT_U32_F32 => f(x).clamp(0.0, u32::MAX as f32) as u32,
                    17..=20 => (((x >> (8 * (o - 17))) & 0xFF) as f32).to_bits(),
                    op::V_FRACT_F32 => (f(x) - f(x).floor()).to_bits(),
                    op::V_FLOOR_F32 => f(x).floor().to_bits(),
                    _ => panic!("VOP1 {o}"),
                };
            }
            pc += 1 + usize::from(a == 255);
        } else if i >> 25 == 0x3E {
            // VOPC.
            let (o, b, a) = ((i >> 17) & 0xFF, ((i >> 9) & 0xFF) as usize, i & 0x1FF);
            let lit = next(1);
            let mut vcc = 0;
            for lane in lanes(w) {
                let (x, y) = (w.src(a, lane, lit), w.v[b][lane]);
                let r = match o {
                    op::V_CMP_GT_U32 => x > y,
                    _ => panic!("VOPC {o}"),
                };
                vcc |= u32::from(r) << lane;
            }
            w.s[106] = vcc;
            pc += 1 + usize::from(a == 255);
        } else if i >> 31 == 0 {
            // VOP2.
            let (o, vdst, b, a) =
                ((i >> 25) & 0x3F, ((i >> 17) & 0xFF) as usize, ((i >> 9) & 0xFF) as usize, i & 0x1FF);
            let lit = next(1);
            for lane in lanes(w) {
                let (x, y) = (w.src(a, lane, lit), w.v[b][lane]);
                w.v[vdst][lane] = vop2(o, x, y);
            }
            pc += 1 + usize::from(a == 255);
        } else if i >> 26 == 0x35 {
            // VOP3.
            let (o, vdst) = ((i >> 16) & 0x3FF, (i & 0xFF) as usize);
            let s = next(1);
            let (a, b, c) = (s & 0x1FF, (s >> 9) & 0x1FF, (s >> 18) & 0x1FF);
            assert_eq!(s >> 27, 0, "no OMOD or NEG");
            let lit = next(2);
            for lane in lanes(w) {
                let (x, y, z) = (w.src(a, lane, lit), w.src(b, lane, lit), w.src(c, lane, lit));
                w.v[vdst][lane] = match o {
                    op::V_MAD_U32_U24 => (x & 0xFF_FFFF).wrapping_mul(y & 0xFF_FFFF).wrapping_add(z),
                    op::V_FMA_F32 => f(x).mul_add(f(y), f(z)).to_bits(),
                    op::V_CVT_PK_U8_F32 => {
                        let sh = 8 * (y & 3);
                        let byte = u32::from(crate::rdna2::to_byte(f(x)));
                        (z & !(0xFF << sh)) | (byte << sh)
                    }
                    256..=319 => vop2(o - 256, x, y),
                    _ => panic!("VOP3 {o}"),
                };
            }
            pc += 2 + usize::from(a == 255 || b == 255 || c == 255);
        } else if i >> 26 == 0x37 {
            // GLOBAL.
            let (o, seg, imm) = ((i >> 18) & 0x7F, (i >> 14) & 3, ((i & 0xFFF) << 20) as i32 >> 20);
            assert_eq!(seg, 2, "GLOBAL only");
            let s = next(1);
            let (addr, data, saddr, vdst) =
                ((s & 0xFF) as usize, ((s >> 8) & 0xFF) as usize, ((s >> 16) & 0x7F) as usize, (s >> 24) as usize);
            for lane in lanes(w) {
                let at = if saddr == 125 || saddr == 0x7F {
                    u64::from(w.v[addr][lane]) | (u64::from(w.v[addr + 1][lane]) << 32)
                } else {
                    (u64::from(w.s[saddr]) | (u64::from(w.s[saddr + 1]) << 32)) + u64::from(w.v[addr][lane])
                };
                let at = (at as i64 + i64::from(imm)) as u64;
                assert_eq!(at % 4, 0, "dword aligned");
                match o {
                    op::GLOBAL_LOAD_DWORD => w.v[vdst][lane] = *mem.get(&at).unwrap_or(&0),
                    op::GLOBAL_STORE_DWORD => {
                        mem.insert(at, w.v[data][lane]);
                    }
                    _ => panic!("GLOBAL {o}"),
                }
            }
            pc += 2;
        } else {
            panic!("an encoding the interpreter doesn't know: {i:#010x} at {pc}");
        }
    }
    panic!("the program didn't end");
}

fn lanes(w: &Wave) -> impl Iterator<Item = usize> + use<> {
    let exec = w.exec();
    (0..32).filter(move |&l| exec & (1 << l) != 0)
}

fn vop2(o: u32, x: u32, y: u32) -> u32 {
    match o {
        op::V_ADD_F32 => (f(x) + f(y)).to_bits(),
        op::V_SUB_F32 => (f(x) - f(y)).to_bits(),
        op::V_MUL_F32 => (f(x) * f(y)).to_bits(),
        op::V_MUL_U32_U24 => (x & 0xFF_FFFF).wrapping_mul(y & 0xFF_FFFF),
        op::V_MIN_I32 => (x as i32).min(y as i32) as u32,
        op::V_MAX_I32 => (x as i32).max(y as i32) as u32,
        op::V_MIN_U32 => x.min(y),
        op::V_LSHRREV_B32 => y >> (x & 31),
        op::V_LSHLREV_B32 => y << (x & 31),
        op::V_AND_B32 => x & y,
        op::V_ADD_NC_U32 => x.wrapping_add(y),
        op::V_SUB_NC_U32 => x.wrapping_sub(y),
        _ => panic!("VOP2 {o}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdna2;

    #[test]
    fn the_fill_fills() {
        let mut mem = HashMap::new();
        let base = 0xF4_0000_0000u64;
        let d = Dispatch {
            program: &rdna2::fill(),
            user: &[base as u32, (base >> 32) as u32, 0x5EED_0FF5],
            threads: 64,
            groups: (16, 1),
            tgid_y: false,
        };
        run(&d, &mut mem);
        assert_eq!(mem.len(), 1024);
        assert!((0..1024).all(|i| mem[&(base + 4 * i)] == 0x5EED_0FF5));
    }

    #[test]
    fn the_blend_is_the_cpus() {
        // A 70 x 3 rectangle at (5, 2) of 100-pixel-wide images; outside
        // it the destination stays.
        let (src, dst, pitch) = (0x1_0000_0000u64, 0x2_0000_0000u64, 400u32);
        let mut mem = HashMap::new();
        let s = |x: u32, y: u32| (((x * 7 + y * 13) & 0xFF) << 24) | (((x * 3) & 0xFF) << 16) | ((y * 50) << 8) | 0x10;
        let d = |x: u32, y: u32| 0xFF00_0000 | ((x + y) & 0xFF) << 16 | 0x8040;
        for y in 0..8 {
            for x in 0..100 {
                mem.insert(src + u64::from(y * pitch + x * 4), s(x, y));
                mem.insert(dst + u64::from(y * pitch + x * 4), d(x, y));
            }
        }
        // Premultiply the source as Strata's pixels are.
        for y in 0..8 {
            for x in 0..100 {
                let p = s(x, y);
                let a = p >> 24;
                let pm = |c: u32| (c * a + 127) / 255;
                let q = (a << 24) | pm((p >> 16) & 0xFF) << 16 | pm((p >> 8) & 0xFF) << 8 | pm(p & 0xFF);
                mem.insert(src + u64::from(y * pitch + x * 4), q);
            }
        }
        let before = mem.clone();
        let k = 0.75f32;
        let at = |base: u64| base + u64::from(2 * pitch + 5 * 4);
        let (sa, da) = (at(src), at(dst));
        let user = [sa as u32, (sa >> 32) as u32, da as u32, (da >> 32) as u32, pitch, pitch, 70, k.to_bits()];
        assert_eq!(user.len() as u32, rdna2::BLEND_USER_SGPRS);
        let prog = rdna2::blend();
        run(&Dispatch { program: &prog, user: &user, threads: 64, groups: (2, 3), tgid_y: true }, &mut mem);
        for y in 0..8 {
            for x in 0..100 {
                let a = dst + u64::from(y * pitch + x * 4);
                let want = if (5..75).contains(&x) && (2..5).contains(&y) {
                    rdna2::blend_pixel(before[&(src + u64::from(y * pitch + x * 4))], before[&a], k)
                } else {
                    before[&a]
                };
                assert_eq!(mem[&a], want, "({x}, {y})");
            }
        }
        // The straight variant on the same images (not premultiplied), and
        // over an opaque pixel its alpha stays 255.
        let mut mem2 = before.clone();
        let prog = rdna2::blend_straight();
        run(&Dispatch { program: &prog, user: &user, threads: 64, groups: (2, 3), tgid_y: true }, &mut mem2);
        for y in 2..5 {
            for x in 5..75 {
                let a = dst + u64::from(y * pitch + x * 4);
                let want = rdna2::blend_straight_pixel(before[&(src + u64::from(y * pitch + x * 4))], before[&a], k);
                assert_eq!(mem2[&a], want, "straight ({x}, {y})");
                assert_eq!(mem2[&a] >> 24, 0xFF, "opaque");
            }
        }
        assert_eq!(rdna2::blend_straight_pixel(0x80FF_0000, 0xFF00_00FF, 1.0), 0xFF80_007F);
        // And the reference itself: opaque white over anything is white,
        // nothing over anything leaves it.
        assert_eq!(rdna2::blend_pixel(0xFFFF_FFFF, 0xFF12_3456, 1.0), 0xFFFF_FFFF);
        assert_eq!(rdna2::blend_pixel(0, 0xFF12_3456, 1.0), 0xFF12_3456);
    }
}
