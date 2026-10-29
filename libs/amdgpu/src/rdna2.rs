// SPDX-License-Identifier: MIT OR Apache-2.0

//! Slate's own RDNA 2 shaders (ADR 0172, M32 phase 6, step 5): an encoder
//! for the few instructions they use, and the shaders themselves.
//!
//! Facts from AMD's RDNA 2 Shader ISA guide and its machine-readable ISA
//! (`amdgpu_isa_rdna2.xml`, MIT; docs/gpu/SOURCES.md): the encodings'
//! fields (ENC_SOPP, ENC_SOPK, ENC_VOP1, ENC_VOP2, ENC_FLAT_GLBL), the
//! opcodes (the XML's `<Opcode>` per instruction, checked by a test when
//! the XML is in target/), the operand codes (SGPRs 0 to 105, NULL 125,
//! inline integers 128 to 192, a literal 255, VGPRs from 256 in a VOP's
//! 9-bit source), and that a program ends with 64 dwords of S_CODE_END
//! for the instruction prefetch (the guide's section 2.5).

use alloc::vec::Vec;

/// A source operand: an SGPR, an inline integer (0 to 64), a 32-bit
/// literal (in the dword after the instruction), or a VGPR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    S(u8),
    Int(u8),
    Literal(u32),
    V(u8),
    /// An inline constant by its code (240 0.5, 242 1.0, 243 -1.0, ...).
    Code(u16),
}

impl Src {
    /// Its 9-bit code in a VOP's source field.
    fn code(self) -> u32 {
        match self {
            Src::S(n) => u32::from(n),
            Src::Int(n) => 128 + u32::from(n.min(64)),
            Src::Literal(_) => 255,
            Src::V(n) => 256 + u32::from(n),
            Src::Code(c) => u32::from(c),
        }
    }

    /// A 32-bit float as a literal.
    pub fn float(f: f32) -> Src {
        Src::Literal(f.to_bits())
    }
}

/// The inline constant 1.0.
pub const ONE: Src = Src::Code(242);
/// VCC's low half and EXEC's (wave32), as SGPR codes.
pub const VCC_LO: u8 = 106;
pub const EXEC_LO: u8 = 126;

/// The SGPR code that reads 0 and drops writes (and turns SADDR off).
pub const NULL: u8 = 125;

/// Opcodes (amdgpu_isa_rdna2.xml), by encoding.
pub mod op {
    // SOPP.
    pub const S_ENDPGM: u32 = 1;
    pub const S_BRANCH: u32 = 2;
    pub const S_CBRANCH_SCC1: u32 = 5;
    pub const S_CBRANCH_EXECZ: u32 = 8;
    pub const S_WAITCNT: u32 = 12;
    pub const S_CODE_END: u32 = 31;
    // SOPK.
    pub const S_WAITCNT_VSCNT: u32 = 23;
    // SOP1.
    pub const S_MOV_B32: u32 = 3;
    pub const S_AND_SAVEEXEC_B32: u32 = 60;
    // SOP2.
    pub const S_ADD_U32: u32 = 0;
    // SOPC.
    pub const S_CMP_LT_U32: u32 = 10;
    // VOP1.
    pub const V_MOV_B32: u32 = 1;
    pub const V_CVT_F32_U32: u32 = 6;
    pub const V_CVT_U32_F32: u32 = 7;
    pub const V_CVT_F32_UBYTE0: u32 = 17;
    pub const V_FRACT_F32: u32 = 32;
    pub const V_FLOOR_F32: u32 = 36;
    // VOP2.
    pub const V_ADD_F32: u32 = 3;
    pub const V_SUB_F32: u32 = 4;
    pub const V_MUL_F32: u32 = 8;
    pub const V_MUL_U32_U24: u32 = 11;
    pub const V_MIN_I32: u32 = 17;
    pub const V_MAX_I32: u32 = 18;
    pub const V_MIN_U32: u32 = 19;
    pub const V_LSHRREV_B32: u32 = 22;
    pub const V_LSHLREV_B32: u32 = 26;
    pub const V_AND_B32: u32 = 27;
    pub const V_ADD_NC_U32: u32 = 37;
    pub const V_SUB_NC_U32: u32 = 38;
    // VOPC.
    pub const V_CMP_GT_U32: u32 = 196;
    // VOP3.
    pub const V_MAD_U32_U24: u32 = 323;
    pub const V_FMA_F32: u32 = 331;
    pub const V_CVT_PK_U8_F32: u32 = 350;
    // FLAT (GLOBAL).
    pub const GLOBAL_LOAD_DWORD: u32 = 12;
    pub const GLOBAL_STORE_DWORD: u32 = 28;
}

/// A shader being written, a dword at a time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Program {
    pub words: Vec<u32>,
}

impl Program {
    /// ENC_SOPP: 1_0111_1111 at bits 23 to 31, the opcode at 16, SIMM16.
    fn sopp(&mut self, op: u32, simm: u16) {
        self.words.push((0x17F << 23) | (op << 16) | u32::from(simm));
    }

    /// ENC_SOPK: 1011 at bits 28 to 31, the opcode at 23, SDST at 16,
    /// SIMM16.
    fn sopk(&mut self, op: u32, sdst: u8, simm: u16) {
        self.words.push((0xB << 28) | (op << 23) | (u32::from(sdst) << 16) | u32::from(simm));
    }

    fn literal(&mut self, src: Src) {
        if let Src::Literal(v) = src {
            self.words.push(v);
        }
    }

    /// ENC_VOP1: 011_1111 at bits 25 to 31, VDST at 17, the opcode at 9,
    /// SRC0 at 0.
    fn vop1(&mut self, op: u32, vdst: u8, src0: Src) {
        self.words.push((0x3F << 25) | (u32::from(vdst) << 17) | (op << 9) | src0.code());
        self.literal(src0);
    }

    /// ENC_VOP2: 0 at bit 31, the opcode at 25, VDST at 17, VSRC1 (a VGPR)
    /// at 9, SRC0 at 0.
    fn vop2(&mut self, op: u32, vdst: u8, src0: Src, vsrc1: u8) {
        self.words.push((op << 25) | (u32::from(vdst) << 17) | (u32::from(vsrc1) << 9) | src0.code());
        self.literal(src0);
    }

    /// ENC_SOP1: 1_0111_1101 at bits 23 to 31, SDST at 16, the opcode at
    /// 8, SSRC0.
    fn sop1(&mut self, op: u32, sdst: u8, src: Src) {
        self.words.push((0x17D << 23) | (u32::from(sdst) << 16) | (op << 8) | src.code());
        self.literal(src);
    }

    /// ENC_SOP2: 10 at bits 30 and 31, the opcode at 23, SDST at 16, SSRC1
    /// at 8, SSRC0.
    fn sop2(&mut self, op: u32, sdst: u8, a: Src, b: Src) {
        self.words.push((2 << 30) | (op << 23) | (u32::from(sdst) << 16) | (b.code() << 8) | a.code());
        self.literal(a);
        self.literal(b);
    }

    /// ENC_SOPC: 1_0111_1110 at bits 23 to 31, the opcode at 16, SSRC1 at
    /// 8, SSRC0.
    fn sopc(&mut self, op: u32, a: Src, b: Src) {
        self.words.push((0x17E << 23) | (op << 16) | (b.code() << 8) | a.code());
        self.literal(a);
        self.literal(b);
    }

    /// ENC_VOPC: 011_1110 at bits 25 to 31, the opcode at 17, VSRC1 at 9,
    /// SRC0 (the result in VCC).
    fn vopc(&mut self, op: u32, src0: Src, vsrc1: u8) {
        self.words.push((0x3E << 25) | (op << 17) | (u32::from(vsrc1) << 9) | src0.code());
        self.literal(src0);
    }

    /// ENC_VOP3: 11_0101 at bits 26 to 31, the opcode at 16, VDST; SRC0,
    /// SRC1 and SRC2 at 0, 9 and 18 of the second dword; a literal (at
    /// most one) after.
    fn vop3(&mut self, op: u32, vdst: u8, a: Src, b: Src, c: Src) {
        self.words.push((0x35 << 26) | (op << 16) | u32::from(vdst));
        self.words.push(a.code() | (b.code() << 9) | (c.code() << 18));
        for s in [a, b, c] {
            self.literal(s);
        }
    }

    /// Where the next instruction goes (for branches), in dwords.
    pub fn here(&self) -> usize {
        self.words.len()
    }

    /// A SOPP branch to `target` (a [`Program::here`]): SIMM16 is the
    /// distance in dwords from the instruction after it.
    fn branch(&mut self, op: u32, target: usize) {
        let offset = target as i64 - (self.words.len() as i64 + 1);
        self.sopp(op, offset as i16 as u16);
    }

    pub fn s_branch(&mut self, target: usize) {
        self.branch(op::S_BRANCH, target);
    }

    pub fn s_cbranch_scc1(&mut self, target: usize) {
        self.branch(op::S_CBRANCH_SCC1, target);
    }

    pub fn s_mov_b32(&mut self, sdst: u8, src: Src) {
        self.sop1(op::S_MOV_B32, sdst, src);
    }

    /// Keep EXEC in `sdst`, then EXEC &= `src`.
    pub fn s_and_saveexec_b32(&mut self, sdst: u8, src: Src) {
        self.sop1(op::S_AND_SAVEEXEC_B32, sdst, src);
    }

    pub fn s_add_u32(&mut self, sdst: u8, a: Src, b: Src) {
        self.sop2(op::S_ADD_U32, sdst, a, b);
    }

    /// SCC = a < b (unsigned).
    pub fn s_cmp_lt_u32(&mut self, a: Src, b: Src) {
        self.sopc(op::S_CMP_LT_U32, a, b);
    }

    /// VCC = src0 > vsrc1 (unsigned), each lane.
    pub fn v_cmp_gt_u32(&mut self, src0: Src, vsrc1: u8) {
        self.vopc(op::V_CMP_GT_U32, src0, vsrc1);
    }

    /// A VOP1 conversion or move.
    pub fn vop1_op(&mut self, op: u32, vdst: u8, src: Src) {
        self.vop1(op, vdst, src);
    }

    /// A VOP2 operation: vdst = src0 op vsrc1.
    pub fn vop2_op(&mut self, op: u32, vdst: u8, src0: Src, vsrc1: u8) {
        self.vop2(op, vdst, src0, vsrc1);
    }

    /// vdst = a * b + c, 24-bit unsigned.
    pub fn v_mad_u32_u24(&mut self, vdst: u8, a: Src, b: Src, c: Src) {
        self.vop3(op::V_MAD_U32_U24, vdst, a, b, c);
    }

    /// vdst = a * b + c, fused.
    pub fn v_fma_f32(&mut self, vdst: u8, a: Src, b: Src, c: Src) {
        self.vop3(op::V_FMA_F32, vdst, a, b, c);
    }

    /// vdst = `into` with byte `byte` replaced by `value` (a float) as an
    /// unsigned byte (rounded to nearest, clamped).
    pub fn v_cvt_pk_u8_f32(&mut self, vdst: u8, value: Src, byte: u8, into: Src) {
        self.vop3(op::V_CVT_PK_U8_F32, vdst, value, Src::Int(byte), into);
    }

    /// Load the dword at SGPRs `saddr`..`saddr` + 1 plus VGPR `offset`
    /// plus `imm` into VGPR `vdst` (ENC_FLAT_GLBL, VDST at 56).
    pub fn global_load_dword(&mut self, vdst: u8, offset: u8, saddr: u8, imm: i16) {
        self.words.push((0x37 << 26) | (op::GLOBAL_LOAD_DWORD << 18) | (2 << 14) | (imm as u32 & 0xFFF));
        self.words.push(u32::from(offset) | (u32::from(saddr) << 16) | (u32::from(vdst) << 24));
    }

    pub fn s_endpgm(&mut self) {
        self.sopp(op::S_ENDPGM, 0);
    }

    /// Wait for every count to reach 0 (S_WAITCNT 0).
    pub fn s_waitcnt_all(&mut self) {
        self.sopp(op::S_WAITCNT, 0);
    }

    /// Wait for the stores (VSCNT) to reach 0: S_WAITCNT_VSCNT null, 0.
    pub fn s_waitcnt_vscnt(&mut self) {
        self.sopk(op::S_WAITCNT_VSCNT, NULL, 0);
    }

    pub fn v_mov_b32(&mut self, vdst: u8, src: Src) {
        self.vop1(op::V_MOV_B32, vdst, src);
    }

    /// vdst = vsrc1 << src0.
    pub fn v_lshlrev_b32(&mut self, vdst: u8, shift: Src, vsrc1: u8) {
        self.vop2(op::V_LSHLREV_B32, vdst, shift, vsrc1);
    }

    /// vdst = src0 + vsrc1 (no carry).
    pub fn v_add_nc_u32(&mut self, vdst: u8, src0: Src, vsrc1: u8) {
        self.vop2(op::V_ADD_NC_U32, vdst, src0, vsrc1);
    }

    /// Store VGPR `data` at the address SGPRs `saddr` and `saddr` + 1
    /// hold plus VGPR `offset` (bytes) plus `imm` (12 bits, signed):
    /// ENC_FLAT_GLBL (11_0111 at bits 26 to 31, the opcode at 18, SEG 2
    /// (global) at 14, OFFSET at 0; ADDR at 32, DATA at 40, SADDR at 48).
    pub fn global_store_dword(&mut self, offset: u8, data: u8, saddr: u8, imm: i16) {
        self.words.push((0x37 << 26) | (op::GLOBAL_STORE_DWORD << 18) | (2 << 14) | (imm as u32 & 0xFFF));
        self.words.push(u32::from(offset) | (u32::from(data) << 8) | (u32::from(saddr) << 16));
    }

    /// The program as it is loaded: its words, then 64 dwords of
    /// S_CODE_END.
    pub fn finish(mut self) -> Vec<u32> {
        for _ in 0..64 {
            self.sopp(op::S_CODE_END, 0);
        }
        self.words
    }
}

/// A fill, wave32, one dword a thread: with the buffer's address in
/// s[0:1] (user data 0 and 1) and the value in s2 (user data 2), thread
/// `i` of thread group `g` (in s3, TGID_X after the three user SGPRs)
/// stores the value at byte `(g * 64 + i) * 4`; 64 threads a group.
pub fn fill() -> Vec<u32> {
    let mut p = Program::default();
    // v1 = g * 64 (s3 << 6), v1 = v1 + tid, v1 = v1 * 4.
    p.v_mov_b32(1, Src::S(3));
    p.v_lshlrev_b32(1, Src::Int(6), 1);
    p.v_add_nc_u32(1, Src::V(0), 1);
    p.v_lshlrev_b32(1, Src::Int(2), 1);
    p.v_mov_b32(2, Src::S(2));
    p.global_store_dword(1, 2, 0, 0);
    p.s_waitcnt_vscnt();
    p.s_endpgm();
    p.finish()
}

/// The blend's user SGPRs: the source's and the destination's addresses
/// at the rectangle's top left (s[0:1], s[2:3]), their pitches in bytes
/// (s4, s5), the rectangle's width (s6) and the opacity as a factor (s7, a
/// float, 0 to 1); then the group's X and Y IDs (s8, s9).
pub const BLEND_USER_SGPRS: u32 = 8;

/// Premultiplied source over destination with an opacity `k`, wave32,
/// 64 threads a group across, a group a row: each channel becomes
/// `d * (1 - sa * k / 255) + s * k`, rounded to the nearest byte (`sa` the
/// source's alpha). Threads past the width do nothing.
pub fn blend() -> Vec<u32> {
    blend_shader(false)
}

/// [`blend`] for a source that isn't premultiplied (slate-ui's colours):
/// each colour channel `d * (1 - f) + s * f` with `f = sa * k / 255`, the
/// alpha `da * (1 - f) + sa * k` (255 over an opaque pixel, as slate-ui's
/// `over_opaque` gives).
pub fn blend_straight() -> Vec<u32> {
    blend_shader(true)
}

fn blend_shader(straight: bool) -> Vec<u32> {
    let mut p = Program::default();
    // x = group X * 64 + thread; lanes past the width off.
    p.v_mov_b32(1, Src::S(8));
    p.v_lshlrev_b32(1, Src::Int(6), 1);
    p.v_add_nc_u32(1, Src::V(0), 1);
    p.v_cmp_gt_u32(Src::S(6), 1);
    p.s_and_saveexec_b32(10, Src::S(VCC_LO));
    // The pixels' offsets: y * pitch + x * 4.
    p.v_lshlrev_b32(2, Src::Int(2), 1);
    p.v_mad_u32_u24(3, Src::S(9), Src::S(4), Src::V(2));
    p.v_mad_u32_u24(4, Src::S(9), Src::S(5), Src::V(2));
    p.global_load_dword(5, 3, 0, 0);
    p.global_load_dword(6, 4, 2, 0);
    p.s_waitcnt_all();
    // v9 = 1 - sa * k / 255 (multiplies and adds, each rounded, so that
    // the CPU's reference is the same without a fused multiply-add).
    p.vop1_op(op::V_CVT_F32_UBYTE0 + 3, 8, Src::V(5));
    p.vop2_op(op::V_MUL_F32, 8, Src::S(7), 8);
    p.vop2_op(op::V_MUL_F32, 9, Src::float(-1.0 / 255.0), 8);
    p.vop2_op(op::V_ADD_F32, 9, ONE, 9);
    // The colour channels' weight: k, or f = sa * k / 255.
    let weight = if straight {
        p.vop2_op(op::V_MUL_F32, 12, Src::float(1.0 / 255.0), 8);
        Src::V(12)
    } else {
        Src::S(7)
    };
    p.v_mov_b32(7, Src::Int(0));
    for c in 0..4u8 {
        p.vop1_op(op::V_CVT_F32_UBYTE0 + u32::from(c), 11, Src::V(6));
        p.vop2_op(op::V_MUL_F32, 11, Src::V(9), 11);
        if straight && c == 3 {
            // The alpha's: sa * k.
            p.v_mov_b32(10, Src::V(8));
        } else {
            p.vop1_op(op::V_CVT_F32_UBYTE0 + u32::from(c), 10, Src::V(5));
            p.vop2_op(op::V_MUL_F32, 10, weight, 10);
        }
        p.vop2_op(op::V_ADD_F32, 10, Src::V(11), 10);
        p.v_cvt_pk_u8_f32(7, Src::V(10), c, Src::V(7));
    }
    p.global_store_dword(4, 7, 2, 0);
    p.s_waitcnt_vscnt();
    p.s_endpgm();
    p.finish()
}

/// What [`blend`] makes of one pixel (the CPU's reference: the same
/// float operations in the same order).
pub fn blend_pixel(s: u32, d: u32, k: f32) -> u32 {
    blend_any(s, d, k, false)
}

/// What [`blend_straight`] makes of one pixel.
pub fn blend_straight_pixel(s: u32, d: u32, k: f32) -> u32 {
    blend_any(s, d, k, true)
}

fn blend_any(s: u32, d: u32, k: f32, straight: bool) -> u32 {
    let sa = k * ((s >> 24) as f32);
    let inv = 1.0 + (-1.0 / 255.0) * sa;
    let weight = if straight { (1.0 / 255.0) * sa } else { k };
    let mut out = 0;
    for c in 0..4 {
        let dc = inv * (((d >> (8 * c)) & 0xFF) as f32);
        let sc = if straight && c == 3 { sa } else { weight * (((s >> (8 * c)) & 0xFF) as f32) };
        out |= u32::from(to_byte(dc + sc)) << (8 * c);
    }
    out
}

/// A float to an unsigned byte, rounded to the nearest (ties to even),
/// clamped: V_CVT_PK_U8_F32's conversion.
pub fn to_byte(v: f32) -> u8 {
    if v.is_nan() || v <= 0.0 {
        return 0;
    }
    if v >= 255.0 {
        return 255;
    }
    let i = v as u32;
    let frac = v - i as f32;
    let up = frac > 0.5 || (frac == 0.5 && i % 2 == 1);
    (i + u32::from(up)).min(255) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        let mut p = Program::default();
        p.s_endpgm();
        p.s_waitcnt_vscnt();
        p.v_mov_b32(2, Src::Literal(0xCAFE_BABE));
        p.v_lshlrev_b32(1, Src::Int(2), 0);
        p.v_add_nc_u32(1, Src::V(0), 1);
        p.global_store_dword(1, 2, 0, 0);
        assert_eq!(
            p.words,
            [0xBF81_0000, 0xBBFD_0000, 0x7E04_02FF, 0xCAFE_BABE, 0x3402_0082, 0x4A02_0300, 0xDC70_8000, 0x0000_0201]
        );
        let f = fill();
        assert_eq!(f.len(), 9 + 64, "eight instructions (the store two dwords), the padding");
        assert_eq!(f[f.len() - 1], 0xBF9F_0000, "S_CODE_END");
        assert_eq!(f.iter().filter(|&&w| w == 0xBF81_0000).count(), 1);
    }

    /// The opcodes as AMD's machine-readable ISA has them, when it is in
    /// target/gpu/sources/amd-isa (AMD's file, never committed).
    #[test]
    fn opcodes_as_amds_xml_has_them() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/gpu/sources/amd-isa/amdgpu_isa_rdna2.xml");
        let Ok(xml) = std::fs::read_to_string(path) else { return };
        let opcode = |name: &str, encoding: &str| -> Option<u32> {
            let at = xml.find(&std::format!("<InstructionName>{name}</InstructionName>"))?;
            let rest = &xml[at..];
            let end = rest.find("</Instruction>")?;
            let rest = &rest[..end];
            let e = rest.find(&std::format!("<EncodingName>{encoding}</EncodingName>"))?;
            let o = rest[e..].find("<Opcode Radix=\"10\">")? + e + "<Opcode Radix=\"10\">".len();
            rest[o..].split('<').next()?.parse().ok()
        };
        for (name, enc, want) in [
            ("S_ENDPGM", "ENC_SOPP", op::S_ENDPGM),
            ("S_WAITCNT", "ENC_SOPP", op::S_WAITCNT),
            ("S_CODE_END", "ENC_SOPP", op::S_CODE_END),
            ("S_WAITCNT_VSCNT", "ENC_SOPK", op::S_WAITCNT_VSCNT),
            ("V_MOV_B32", "ENC_VOP1", op::V_MOV_B32),
            ("V_LSHLREV_B32", "ENC_VOP2", op::V_LSHLREV_B32),
            ("V_ADD_NC_U32", "ENC_VOP2", op::V_ADD_NC_U32),
            ("GLOBAL_STORE_DWORD", "ENC_FLAT_GLBL", op::GLOBAL_STORE_DWORD),
            ("GLOBAL_LOAD_DWORD", "ENC_FLAT_GLBL", op::GLOBAL_LOAD_DWORD),
            ("S_BRANCH", "ENC_SOPP", op::S_BRANCH),
            ("S_CBRANCH_SCC1", "ENC_SOPP", op::S_CBRANCH_SCC1),
            ("S_CBRANCH_EXECZ", "ENC_SOPP", op::S_CBRANCH_EXECZ),
            ("S_MOV_B32", "ENC_SOP1", op::S_MOV_B32),
            ("S_AND_SAVEEXEC_B32", "ENC_SOP1", op::S_AND_SAVEEXEC_B32),
            ("S_ADD_U32", "ENC_SOP2", op::S_ADD_U32),
            ("S_CMP_LT_U32", "ENC_SOPC", op::S_CMP_LT_U32),
            ("V_CVT_F32_U32", "ENC_VOP1", op::V_CVT_F32_U32),
            ("V_CVT_U32_F32", "ENC_VOP1", op::V_CVT_U32_F32),
            ("V_CVT_F32_UBYTE0", "ENC_VOP1", op::V_CVT_F32_UBYTE0),
            ("V_CVT_F32_UBYTE3", "ENC_VOP1", op::V_CVT_F32_UBYTE0 + 3),
            ("V_FRACT_F32", "ENC_VOP1", op::V_FRACT_F32),
            ("V_FLOOR_F32", "ENC_VOP1", op::V_FLOOR_F32),
            ("V_ADD_F32", "ENC_VOP2", op::V_ADD_F32),
            ("V_SUB_F32", "ENC_VOP2", op::V_SUB_F32),
            ("V_MUL_F32", "ENC_VOP2", op::V_MUL_F32),
            ("V_MUL_U32_U24", "ENC_VOP2", op::V_MUL_U32_U24),
            ("V_MIN_I32", "ENC_VOP2", op::V_MIN_I32),
            ("V_MAX_I32", "ENC_VOP2", op::V_MAX_I32),
            ("V_MIN_U32", "ENC_VOP2", op::V_MIN_U32),
            ("V_LSHRREV_B32", "ENC_VOP2", op::V_LSHRREV_B32),
            ("V_AND_B32", "ENC_VOP2", op::V_AND_B32),
            ("V_SUB_NC_U32", "ENC_VOP2", op::V_SUB_NC_U32),
            ("V_CMP_GT_U32", "ENC_VOPC", op::V_CMP_GT_U32),
            ("V_MAD_U32_U24", "ENC_VOP3", op::V_MAD_U32_U24),
            ("V_FMA_F32", "ENC_VOP3", op::V_FMA_F32),
            ("V_CVT_PK_U8_F32", "ENC_VOP3", op::V_CVT_PK_U8_F32),
            ("V_MUL_F32", "ENC_VOP3", op::V_MUL_F32 + 256),
        ] {
            assert_eq!(opcode(name, enc), Some(want), "{name}");
        }
    }
}
