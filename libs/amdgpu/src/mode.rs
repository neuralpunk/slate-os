// SPDX-License-Identifier: MIT OR Apache-2.0

//! A mode on one output of DCN 3.1.5 (ADR 0171, M32 phase 4, step 7):
//! DC's hardware init through DMCUB, a link lit (OTG0, DIG0, a PHY through
//! DMCUB), a linear framebuffer through pipe 0, and the link switched off
//! again. What the driver writes, in DC's order, against a [`Card`] and
//! [`Memory`]; the values are computed here and checked against amdgpu's
//! registers on the reference PC (its 1080p60 on HDMI).
//!
//! Facts from DC and amdgpu (Linux v7.2.12, read as documentation, ADR
//! 0157's addendum; Slate's own code), function by function at each step
//! below; registers from dcn_3_1_5_offset.h and dcn_3_1_5_sh_mask.h (DCN's
//! segments 1, 2 and 3), mp_13_0_5_offset.h and nbio_7_2_0_offset.h.
//! What the reference PC taught (docs/gpu/amd.md): DMCUB's init commands as amdgpu
//! sends them (read from its inbox ring), the SMU out of display idle
//! before the pixel clock, VSTARTUP within vertical blank, the MPC tree
//! before a plane's double-buffered settings can take, and a clean
//! switch-off (a later DMCUB can't switch off a link an earlier one left
//! lit).

use crate::dmub::{self, vbios};
use crate::interp::Card;
use crate::otg::{self, Timing};
use crate::psp::Memory;

/// Register words (dcn_3_1_5_offset.h, by segment).
pub mod reg {
    /// Segment 1 (DCCG).
    pub const OTG0_PIXEL_RATE_CNTL: u32 = 0x80;
    pub const DPPCLK0_DTO_PARAM: u32 = 0x99;
    pub const DPPCLK1_DTO_PARAM: u32 = 0x9A;
    pub const DPPCLK_DTO_CTRL: u32 = 0xB6;
    /// Segment 2.
    pub const DOMAIN0_PG_CONFIG: u32 = 0x80;
    pub const DOMAIN0_PG_STATUS: u32 = 0x81;
    pub const DOMAIN1_PG_CONFIG: u32 = 0x82;
    pub const DOMAIN1_PG_STATUS: u32 = 0x83;
    pub const DC_IP_REQUEST_CNTL: u32 = 0x93;
    pub const COMPBUF_CTRL: u32 = 0x4CB;
    pub const DET0_CTRL: u32 = 0x4CC;
    pub const DET1_CTRL: u32 = 0x4CD;
    pub const VTG0_CONTROL: u32 = 0x52D;
    pub const HUBP0_SURFACE_CONFIG: u32 = 0x5E5;
    pub const HUBP0_TILING_CONFIG: u32 = 0x5E7;
    pub const HUBP0_PRI_VIEWPORT_START: u32 = 0x5E9;
    pub const HUBP0_PRI_VIEWPORT_DIMENSION: u32 = 0x5EA;
    pub const HUBP0_SEC_VIEWPORT_START: u32 = 0x5ED;
    pub const HUBP0_SEC_VIEWPORT_DIMENSION: u32 = 0x5EE;
    pub const HUBP0_REQ_SIZE_CONFIG: u32 = 0x5F1;
    pub const HUBP0_DCHUBP_CNTL: u32 = 0x5F3;
    pub const HUBP0_CLK_CNTL: u32 = 0x5F4;
    pub const HUBP0_HUBPREQ_DEBUG_DB: u32 = 0x5F6;
    pub const HUBP0_HUBPREQ_DEBUG: u32 = 0x5F7;
    pub const HUBPREQ0_SURFACE_PITCH: u32 = 0x607;
    pub const HUBPREQ0_PRIMARY_SURFACE_ADDRESS: u32 = 0x60A;
    pub const HUBPREQ0_PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x60B;
    pub const HUBPREQ0_FLIP_CONTROL: u32 = 0x61B;
    pub const HUBPREQ0_EXPANSION_MODE: u32 = 0x629;
    pub const HUBPREQ0_TTU_QOS_WM: u32 = 0x62A;
    pub const HUBPREQ0_GLOBAL_TTU_CNTL: u32 = 0x62B;
    pub const HUBPREQ0_SURF0_TTU_CNTL0: u32 = 0x62C;
    pub const HUBPREQ0_SURF0_TTU_CNTL1: u32 = 0x62D;
    pub const HUBPREQ0_SYSTEM_APERTURE_LOW: u32 = 0x635;
    pub const HUBPREQ0_SYSTEM_APERTURE_HIGH: u32 = 0x636;
    pub const HUBPREQ0_L1_TLB_CNTL: u32 = 0x643;
    pub const HUBPREQ0_BLANK_OFFSET_0: u32 = 0x644;
    pub const HUBPREQ0_BLANK_OFFSET_1: u32 = 0x645;
    pub const HUBPREQ0_DST_DIMENSIONS: u32 = 0x646;
    pub const HUBPREQ0_DST_AFTER_SCALER: u32 = 0x647;
    pub const HUBPREQ0_PREFETCH_SETTINGS: u32 = 0x648;
    pub const HUBPREQ0_VBLANK_PARAMETERS_0: u32 = 0x64A;
    pub const HUBPREQ0_PER_LINE_DELIVERY_PRE: u32 = 0x65A;
    pub const HUBPREQ0_PER_LINE_DELIVERY: u32 = 0x65B;
    pub const HUBPREQ0_REF_FREQ_TO_PIX_FREQ: u32 = 0x65D;
    pub const HUBPRET0_CONTROL: u32 = 0x66C;
    pub const DPP_TOP0_DPP_CONTROL: u32 = 0xCC5;
    pub const CNVC0_SURFACE_PIXEL_FORMAT: u32 = 0xCCF;
    pub const CNVC0_FORMAT_CONTROL: u32 = 0xCD0;
    pub const DSCL0_SCL_MODE: u32 = 0xCFB;
    pub const DSCL0_SCL_TAP_CONTROL: u32 = 0xCFC;
    pub const DSCL0_2TAP_CONTROL: u32 = 0xCFE;
    pub const DSCL0_HORZ_FILTER_INIT: u32 = 0xD01;
    pub const DSCL0_VERT_FILTER_INIT: u32 = 0xD05;
    pub const DSCL0_RECOUT_START: u32 = 0xD11;
    pub const DSCL0_RECOUT_SIZE: u32 = 0xD12;
    pub const DSCL0_MPC_SIZE: u32 = 0xD13;
    pub const DSCL0_LB_DATA_FORMAT: u32 = 0xD14;
    pub const DSCL0_LB_MEMORY_CTRL: u32 = 0xD15;
    pub const DSCL0_OBUF_CONTROL: u32 = 0xD19;
    pub const DPG0_CONTROL: u32 = 0x1854;
    pub const DPG0_DIMENSIONS: u32 = 0x1856;
    pub const DPG0_OFFSET_SEGMENT: u32 = 0x185A;
    pub const OPTC0_DATA_SOURCE_SELECT: u32 = 0x1ACB;
    pub const OPTC0_INPUT_CLOCK_CONTROL: u32 = 0x1ACF;
    pub const OTG0_STATUS: u32 = 0x1B49;
    pub const OTG0_FRAME_COUNT: u32 = 0x1B4C;
    pub const OTG0_CLOCK_CONTROL: u32 = 0x1B86;
    pub const OTG0_VSTARTUP_PARAM: u32 = 0x1B87;
    pub const OTG0_VUPDATE_PARAM: u32 = 0x1B88;
    pub const OTG0_VREADY_PARAM: u32 = 0x1B89;
    pub const OTG0_MASTER_UPDATE_LOCK: u32 = 0x1B8B;
    pub const DIG0_FE_CNTL: u32 = 0x208B;
    pub const DIG0_FIFO_STATUS: u32 = 0x2091;
    pub const DIG0_HDMI_VBI_PACKET_CONTROL: u32 = 0x2097;
    pub const DIG0_HDMI_GC: u32 = 0x209D;
    pub const DIG0_BE_CNTL: u32 = 0x20B0;
    pub const DIG0_BE_EN_CNTL: u32 = 0x20B1;
    /// Segment 3 (MPC).
    pub const MPCC0_TOP_SEL: u32 = 0x0;
    pub const MPCC0_BOT_SEL: u32 = 0x1;
    pub const MPCC0_OPP_ID: u32 = 0x2;
    pub const MPCC0_CONTROL: u32 = 0x3;
    pub const MPCC0_UPDATE_LOCK_SEL: u32 = 0x5;
    pub const MPCC0_TOP_GAIN: u32 = 0x6;
    pub const MPCC0_BOT_GAIN_INSIDE: u32 = 0x7;
    pub const MPCC0_BOT_GAIN_OUTSIDE: u32 = 0x8;
    pub const MPCC0_STATUS: u32 = 0xD;
    /// MPCC `n`'s registers are MPCC0's plus `n` times this.
    pub const MPCC_STRIDE: u32 = 0x20;
    pub const MPC_OUT0_MUX: u32 = 0x580;
    /// MP0's segment 0 and NBIO's segment 0 (the SMU's mailbox).
    pub const MP1_C2PMSG_37: u32 = 0x265;
    pub const MP1_C2PMSG_38: u32 = 0x266;
    pub const PCIE_INDEX2: u32 = 0xE;
    pub const PCIE_DATA2: u32 = 0xF;
}

/// Pipe `n`'s HUBP and DPP registers (segment 2) are pipe 0's plus `n`
/// times these (dcn_3_1_5_offset.h: HUBP1_DCSURF_SURFACE_CONFIG 6C1h after
/// HUBP0's 5E5h, DPP_TOP1_DPP_CONTROL E30h after DPP_TOP0's CC5h).
pub const HUBP_STRIDE: u32 = 0xDC;
pub const DPP_STRIDE: u32 = 0x16B;

/// Pipe 0's register `r` (segment 2) on pipe `pipe`: HUBP's and DPP's
/// move, the rest (the hub's, the OTG's) stay.
pub const fn on_pipe(r: u32, pipe: u32) -> u32 {
    match r {
        0x5E5..0x6C1 => r + HUBP_STRIDE * pipe,
        0xCC5..0xE30 => r + DPP_STRIDE * pipe,
        _ => r,
    }
}

/// The SMU's messages DC's clock manager sends (dcn315_smu.c).
pub mod smu {
    pub const GET_PMFW_VERSION: u32 = 0x02;
    pub const SET_DISPLAY_IDLE_OPTIMIZATIONS: u32 = 0x12;
    /// `mmMP1_C2PMSG_3`, an SMN address.
    pub const MP1_C2PMSG_3: u32 = 0x03B1_050C;
    pub const OK: u32 = 1;
}

/// Where the blocks are (register words): DCN's segments 1 to 3, MP0's
/// segment 0, NBIO's segment 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bases {
    pub dcn1: u32,
    pub dcn2: u32,
    pub dcn3: u32,
    pub mp0: u32,
    pub nbio0: u32,
}

/// A link: its PHY (0 is UNIPHY A), the connector's and the encoder's
/// object IDs, its HPD pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub phy: u8,
    pub connector: u8,
    pub encoder: u8,
    pub hpd: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// DMCUB didn't take a command (which, of those for this step).
    Dmcub(&'static str),
    /// A clock, a power domain or a buffer didn't come on.
    Stuck(&'static str),
    /// The SMU didn't answer OK (its response).
    Smu(u32),
    /// A timing the OTG can't hold.
    Timing,
}

/// The pieces the steps go through.
pub trait Dev: Card + Memory {}
impl<T: Card + Memory> Dev for T {}

struct Io<'d, D: Card> {
    dev: &'d mut D,
    b: Bases,
}

impl<D: Card> Io<'_, D> {
    fn r1(&mut self, r: u32) -> u32 {
        self.dev.read(self.b.dcn1 + r)
    }
    fn w1(&mut self, r: u32, v: u32) {
        self.dev.write(self.b.dcn1 + r, v)
    }
    fn r2(&mut self, r: u32) -> u32 {
        self.dev.read(self.b.dcn2 + r)
    }
    fn w2(&mut self, r: u32, v: u32) {
        self.dev.write(self.b.dcn2 + r, v)
    }
    fn r3(&mut self, r: u32) -> u32 {
        self.dev.read(self.b.dcn3 + r)
    }
    fn w3(&mut self, r: u32, v: u32) {
        self.dev.write(self.b.dcn3 + r, v)
    }
    fn u1(&mut self, r: u32, clear: u32, set: u32) {
        let v = self.r1(r);
        self.w1(r, (v & !clear) | set);
    }
    fn u2(&mut self, r: u32, clear: u32, set: u32) {
        let v = self.r2(r);
        self.w2(r, (v & !clear) | set);
    }
    /// Wait up to `us` microseconds for `done` on a segment 2 register.
    fn until2(&mut self, r: u32, us: u32, done: impl Fn(u32) -> bool) -> bool {
        for _ in 0..us {
            if done(self.r2(r)) {
                return true;
            }
            self.dev.delay_us(1);
        }
        done(self.r2(r))
    }
}

impl<D: Dev> Io<'_, D> {
    fn send(&mut self, ring: u64, cmd: &[u8; 64], what: &'static str) -> Result<(), Error> {
        dmub::send(self.dev, self.b.dcn2, ring, cmd).map_err(|_| Error::Dmcub(what))
    }
}

/// Send the SMU (MP1) `msg` with `param`, as DC's clock manager does
/// (clk_mgr/dcn315/dcn315_smu.c, `dcn315_smu_send_msg_with_param`: wait
/// for C2PMSG_38 to stop reading 0 (busy), clear it, the parameter into
/// C2PMSG_37, the message's ID into `MP1_C2PMSG_3` (an SMN address,
/// through NBIO's PCIe index and data pair, as amdgpu_device.c's
/// `amdgpu_device_indirect_wreg` writes it), wait for the response). Its
/// reply (C2PMSG_37) or the response that wasn't OK.
pub fn smu_message(dev: &mut impl Card, b: Bases, msg: u32, param: u32) -> Result<u32, Error> {
    let wait = |dev: &mut _| {
        for _ in 0..200_000 {
            let v = Card::read(dev, b.mp0 + reg::MP1_C2PMSG_38);
            if v != 0 {
                return v;
            }
            Card::delay_us(dev, 10);
        }
        0
    };
    wait(dev);
    dev.write(b.mp0 + reg::MP1_C2PMSG_38, 0);
    dev.write(b.mp0 + reg::MP1_C2PMSG_37, param);
    dev.write(b.nbio0 + reg::PCIE_INDEX2, smu::MP1_C2PMSG_3);
    dev.read(b.nbio0 + reg::PCIE_INDEX2);
    dev.write(b.nbio0 + reg::PCIE_DATA2, msg);
    dev.read(b.nbio0 + reg::PCIE_DATA2);
    match wait(dev) {
        smu::OK => Ok(dev.read(b.mp0 + reg::MP1_C2PMSG_37)),
        r => Err(Error::Smu(r)),
    }
}

/// DC's hardware init through DMCUB (its ring at GPU address `ring`), as
/// amdgpu's ring on the reference PC shows it: display power gating INIT for the
/// first pipe and off for the four (dcn10_hwseq.c,
/// `dcn10_bios_golden_init`), the driver in D0 and the init state saved
/// (core/dc.c, `dc_hardware_init`). How many it took.
pub fn init(dev: &mut impl Dev, b: Bases, ring: u64) -> usize {
    let mut cmds = [[0u8; 64]; 7];
    cmds[0] = dmub::power_gating(0, vbios::INIT);
    for p in 0..4 {
        cmds[1 + p] = dmub::power_gating(p as u8, vbios::DISABLE);
    }
    cmds[5] = dmub::typed(dmub::idle::TYPE, dmub::idle::SET_DC_POWER_STATE, &[dmub::idle::D0, 0, 0, 0], 4);
    cmds[6] = dmub::typed(dmub::idle::TYPE, dmub::idle::SAVE_INIT, &[], 0);
    cmds.iter().take_while(|c| dmub::send(dev, b.dcn2, ring, c).is_ok()).count()
}

/// DML's values for a mode that aren't ported yet (its bandwidth model):
/// the global sync (VSTARTUP in lines, VUPDATE's offset and width and
/// VREADY's offset in pixels), the prefetch, QoS and per-request delivery.
/// What DML gives at 1080p60 with DCN 3.1.5's clocks (amdgpu's on the reference PC);
/// VSTARTUP is kept within vertical blank.
struct Dml {
    vstartup: u32,
    vupdate: (u32, u32),
    vready: u32,
    prefetch: u32,
    qos_wm: u32,
    global_ttu: u32,
    expansion: u32,
}

const DML_1080P60: Dml = Dml {
    vstartup: 44,
    vupdate: (550, 251),
    vready: 333,
    prefetch: 0x211E_0000,
    qos_wm: 0x058E_0000,
    global_ttu: 0xE000_310F,
    expansion: 0x56,
};

/// The DLG's reference clock, 24 MHz (the hub's global timer, refdiv 1;
/// dcn31_hubbub.c, `hubbub31_get_dchub_ref_freq`).
const REF_KHZ: u64 = 24_000;

/// What happened when a link was lit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lit {
    pub frames: u32,
    pub dig_fifo: u32,
}

/// The global sync and the VTG for `t` (optc/dcn10/dcn10_optc.c,
/// `optc1_program_global_sync`, `optc1_set_vtg_params`: VCOUNT_INIT at
/// blank's start, FP2 the lines VSTARTUP comes before blank's end).
pub fn global_sync(t: &Timing) -> [(u32, u32); 4] {
    let d = DML_1080P60;
    let v_init = t.vtotal - (t.vsync_start - t.vactive);
    let blank_end = v_init - t.vactive;
    let vstartup = d.vstartup.min(t.vtotal - t.vactive - 1);
    let fp2 = vstartup.saturating_sub(blank_end + 1).min(0x7FFF);
    [
        (reg::OTG0_VSTARTUP_PARAM, vstartup),
        (reg::OTG0_VUPDATE_PARAM, d.vupdate.0 | (d.vupdate.1 << 16)),
        (reg::OTG0_VREADY_PARAM, d.vready),
        (reg::VTG0_CONTROL, fp2 | (v_init << 16)),
    ]
}

/// Light `l` at `t` through OTG0 and DIG0 with the pattern generator's
/// colour squares (no plane yet), in DC's order (dcn20_hwseq.c,
/// `dcn20_enable_stream_timing`; link_dpms.c, `link_set_dpms_on`):
/// - any OTG0 left running stopped (`optc31_disable_crtc`);
/// - the PHY initialised, the link off and every PHY PLL down through
///   DMCUB (`disable_output`, `cs_power_down`; INIT for a PHY an earlier
///   DMCUB may have left on);
/// - the SMU out of display idle, the PHYs' reference clock back
///   (dcn315_clk_mgr.c, `dcn315_update_clocks`);
/// - OPTC's and OTG0's clocks (`optc1_enable_optc_clock`);
/// - the pixel clock from PHY PLL0 (`dcn31_program_pix_clk`: the DTO
///   source 0, then set pixel clock through DMCUB);
/// - the timing, the global sync, the VTG;
/// - pipe 0 powered and clocked (`dcn31_hubp_pg_control`,
///   `dccg31_update_dpp_dto`: FFh/FFh, `dpp1_dppclk_control`), HUBP0
///   blank and timed by OTG0 (`hubp2_clk_cntl`, `hubp2_set_blank_regs`);
/// - the pattern (`opp2_set_disp_pattern_generator`: colour squares,
///   VESA, 8 bits, 6 and 6), OPP0 into OTG0, the VTG on, the OTG on
///   (`optc31_enable_crtc`, disable point 2);
/// - DIG0 in HDMI mode, encoder setup and transmitter ENABLE through
///   DMCUB (`dcn10_link_encoder_setup`, `_enable_tmds_output`: four lanes,
///   the pixel clock as the symbol clock at 8 bits), then the back end on
///   front end 0 and the front end on OTG0 again (`enable_stream`);
/// - HDMI's general control packet without AV mute (`set_avmute`).
pub fn light(dev: &mut impl Dev, b: Bases, ring: u64, l: Link, t: &Timing) -> Result<Lit, Error> {
    let otg_regs = otg::registers(t).ok_or(Error::Timing)?;
    let mut io = Io { dev, b };
    // A running OTG0 stopped first.
    io.u2(otg::reg::CONTROL, 1, 0);
    if !io.until2(otg::reg::CONTROL, 100_000, |v| v & (1 << 16) == 0) {
        return Err(Error::Stuck("OTG0 off"));
    }
    // The link down.
    let init = dmub::transmitter(l.phy, vbios::TRANSMITTER_INIT, 0, 4, 0, l.hpd, l.connector);
    io.send(ring, &init, "PHY init")?;
    let off = dmub::transmitter(l.phy, vbios::TRANSMITTER_DISABLE, vbios::MODE_DVI, 0, 0, l.hpd, l.connector);
    io.send(ring, &off, "link off")?;
    for pll in vbios::COMBOPHY_PLL0..vbios::COMBOPHY_PLL0 + 5 {
        io.send(ring, &dmub::pll_off(pll), "PLL off")?;
    }
    // The display out of idle.
    smu_message(io.dev, b, smu::SET_DISPLAY_IDLE_OPTIMIZATIONS, 0)?;
    // The clocks.
    io.u2(reg::OPTC0_INPUT_CLOCK_CONTROL, 0, 0b11);
    if !io.until2(reg::OPTC0_INPUT_CLOCK_CONTROL, 1000, |v| v & (1 << 2) != 0) {
        return Err(Error::Stuck("OPTC clock"));
    }
    io.u2(reg::OTG0_CLOCK_CONTROL, 0, 0b11);
    if !io.until2(reg::OTG0_CLOCK_CONTROL, 1000, |v| v & (1 << 8) != 0) {
        return Err(Error::Stuck("OTG clock"));
    }
    // The pixel clock.
    io.u1(reg::OTG0_PIXEL_RATE_CNTL, (1 << 12) | (1 << 4), 0);
    let clk =
        dmub::pixel_clock(t.clock_khz * 10, vbios::COMBOPHY_PLL0, l.encoder, vbios::MODE_HDMI, 0, vbios::CRTC1, 0);
    io.send(ring, &clk, "pixel clock")?;
    // The timing, the global sync, the VTG.
    for (r, v) in otg_regs {
        io.w2(r, v);
    }
    let sync = global_sync(t);
    for (r, v) in &sync[..3] {
        io.w2(*r, *v);
    }
    io.u2(reg::VTG0_CONTROL, 0x7FFF_7FFF, sync[3].1);
    // Pipe 0 powered and clocked, HUBP0 blank on OTG0.
    let ip = io.r2(reg::DC_IP_REQUEST_CNTL) & 1;
    io.w2(reg::DC_IP_REQUEST_CNTL, 1);
    io.u2(reg::DOMAIN0_PG_CONFIG, 1 << 8, 0);
    let powered = io.until2(reg::DOMAIN0_PG_STATUS, 1000, |v| v & (3 << 30) == 0);
    io.w2(reg::DC_IP_REQUEST_CNTL, ip);
    if !powered {
        return Err(Error::Stuck("pipe 0 power"));
    }
    io.w1(reg::DPPCLK0_DTO_PARAM, 0x00FF_00FF);
    io.u1(reg::DPPCLK_DTO_CTRL, 0, 1);
    io.u2(reg::DPP_TOP0_DPP_CONTROL, 0, 1 << 4);
    io.u2(reg::HUBP0_CLK_CNTL, 0, 1);
    io.u2(reg::HUBP0_DCHUBP_CNTL, 0xF0 | (1 << 12), 1);
    // The pattern, OPP0 into OTG0, the VTG and the OTG on.
    io.w2(reg::DPG0_DIMENSIONS, t.vactive | (t.hactive << 16));
    io.w2(reg::DPG0_OFFSET_SEGMENT, 0);
    io.u2(reg::DPG0_CONTROL, 0x00FF_3171, 1 | (1 << 12) | (6 << 16) | (6 << 20));
    io.u2(reg::OPTC0_DATA_SOURCE_SELECT, 0xF << 16, 0);
    io.u2(reg::VTG0_CONTROL, 0, 1 << 31);
    io.u2(otg::reg::CONTROL, 0x300, (2 << 8) | 1);
    // DIG0 and the PHY.
    io.u2(reg::DIG0_FE_CNTL, 7, 0);
    io.u2(reg::DIG0_BE_CNTL, 0x7F00 | (7 << 16), (1 << 8) | (3 << 16));
    let symclk_10khz = t.clock_khz / 10;
    let setup = dmub::encoder_setup(0, vbios::MODE_HDMI, 4, symclk_10khz, vbios::BPC_8);
    io.send(ring, &setup, "encoder setup")?;
    let on = dmub::transmitter(l.phy, vbios::TRANSMITTER_ENABLE, vbios::MODE_HDMI, 4, symclk_10khz, l.hpd, 0);
    io.send(ring, &on, "link on")?;
    io.u2(reg::DIG0_BE_CNTL, 0x7F00 | (7 << 16), (1 << 8) | (3 << 16));
    io.u2(reg::DIG0_FE_CNTL, 7, 0);
    io.u2(reg::DIG0_HDMI_VBI_PACKET_CONTROL, 0, 1 << 4);
    io.u2(reg::DIG0_HDMI_GC, 1, 0);
    Ok(Lit { frames: io.r2(reg::OTG0_FRAME_COUNT) & 0xFF_FFFF, dig_fifo: io.r2(reg::DIG0_FIFO_STATUS) })
}

/// A linear 32-bit surface, `pitch` pixels a line, at GPU address
/// `address`; `alpha` if its top byte is alpha (ARGB8888), else it is
/// ignored (XRGB8888).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Surface {
    pub address: u64,
    pub pitch: u32,
    pub alpha: bool,
}

/// The carve-out's GPU addresses (for the system aperture).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aperture {
    pub base: u64,
    pub size: u64,
}

/// Pipe 0's registers (segment 2) for `s` shown at `t`, unscaled
/// (DC: hubp/dcn20/dcn20_hubp.c, dcn30_hubp.c, dpp/dcn30/dcn30_dpp.c,
/// dpp/dcn10/dcn10_dpp_dscl.c; DML's display_rq_dlg_calc_31.c for the
/// deadlines):
/// - HUBP's surface: ARGB8888 (8), linear (swizzle 0), the viewport, the
///   request sizes for a linear surface (swath height 1, no page table
///   rows), the crossbar, the pitch less one, the system aperture over the
///   carve-out (256 KiB units) with the L1 TLB in system access mode 3
///   (`hubp3_set_vm_system_aperture_settings`), the address (high half
///   first);
/// - the deadlines (`hubp2_program_deadline`): blank's end in reference
///   cycles and lines, the next start at blank's start (U?.2), the line's
///   total in reference cycles (U?.8), the reference clock over the pixel
///   clock (U0.19), a line's delivery in reference cycles (half that in
///   prefetch); DML's bandwidth values for this mode;
/// - `hubp3_init`'s chicken bit and `hubp2_vready_at_or_After_vsync`'s;
/// - the DPP (`dpp3_cnv_setup`: format 8, alpha on, crossbar G=1 B=2; the
///   scaler in 4:4:4 bypass, its line buffer, recout and MPC size).
pub fn plane_registers(t: &Timing, s: Surface, ap: Aperture) -> [(u32, u32); 41] {
    placed_registers(t, s, ap, Place { pipe: 0, at: (0, 0), size: (t.hactive, t.vactive) })
}

/// Where a plane goes: its pipe, its top left corner on the screen and
/// its size (unscaled; on the screen).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub pipe: u32,
    pub at: (u32, u32),
    pub size: (u32, u32),
}

/// [`plane_registers`] for a plane `place.size` big at `place.at`
/// through pipe `place.pipe`: the viewport and the scaler's output rectangle (recout) are
/// the plane's, the MPC's size the screen's (dpp/dcn10/dcn10_dpp_dscl.c,
/// `dpp1_dscl_set_recout` and the MPC size from the stream's active
/// area), and a line's delivery is the plane's width (DML's
/// `get_refcyc_per_delivery`: the recout's width over the pixel clock);
/// the rest is the timing's.
pub fn placed_registers(t: &Timing, s: Surface, ap: Aperture, place: Place) -> [(u32, u32); 41] {
    let d = DML_1080P60;
    let (w, h) = place.size;
    let p = u64::from(t.clock_khz);
    let refcyc = |pixels: u64| (pixels * REF_KHZ / p) as u32;
    let hblank_end = t.htotal - t.hsync_start;
    let vblank_end = t.vtotal - t.vsync_start;
    let vblank_start = t.vtotal - (t.vsync_start - t.vactive);
    let size = (h << 16) | w;
    let screen = (t.vactive << 16) | t.hactive;
    // DCN 3.1's pipeline after the scaler: 205 pixels (DML's DPP delays).
    let x_after_scaler = 205;
    // A request carries 8 pixels at this format (DML).
    let per_req = (8 * REF_KHZ * 1024 / p) as u32;
    [
        (reg::HUBP0_SURFACE_CONFIG, 8),
        (reg::HUBP0_TILING_CONFIG, 0),
        (reg::HUBP0_PRI_VIEWPORT_START, 0),
        (reg::HUBP0_PRI_VIEWPORT_DIMENSION, size),
        (reg::HUBP0_SEC_VIEWPORT_START, 0),
        (reg::HUBP0_SEC_VIEWPORT_DIMENSION, size),
        (reg::HUBP0_REQ_SIZE_CONFIG, 0x033D_1B00),
        (reg::HUBPRET0_CONTROL, 0x00E4_0000),
        (reg::HUBPREQ0_SURFACE_PITCH, s.pitch - 1),
        (reg::HUBPREQ0_SYSTEM_APERTURE_LOW, (ap.base >> 18) as u32),
        (reg::HUBPREQ0_SYSTEM_APERTURE_HIGH, ((ap.base + ap.size - 1) >> 18) as u32),
        (reg::HUBPREQ0_L1_TLB_CNTL, 1 | (3 << 3)),
        (reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS_HIGH, (s.address >> 32) as u32),
        (reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS, s.address as u32),
        (reg::HUBPREQ0_BLANK_OFFSET_0, (vblank_end << 16) | refcyc(u64::from(hblank_end))),
        (reg::HUBPREQ0_BLANK_OFFSET_1, vblank_start * 4),
        (reg::HUBPREQ0_DST_DIMENSIONS, (u64::from(t.htotal) * REF_KHZ * 256 / p) as u32),
        (reg::HUBPREQ0_DST_AFTER_SCALER, refcyc(x_after_scaler)),
        (reg::HUBPREQ0_REF_FREQ_TO_PIX_FREQ, (REF_KHZ * (1 << 19) / p) as u32),
        (reg::HUBPREQ0_VBLANK_PARAMETERS_0, 0),
        (reg::HUBPREQ0_PER_LINE_DELIVERY, refcyc(u64::from(w))),
        (reg::HUBPREQ0_PER_LINE_DELIVERY_PRE, refcyc(u64::from(w)) / 2),
        (reg::HUBPREQ0_PREFETCH_SETTINGS, d.prefetch),
        (reg::HUBPREQ0_TTU_QOS_WM, d.qos_wm),
        (reg::HUBPREQ0_SURF0_TTU_CNTL0, 0x0800_0000 | per_req),
        (reg::HUBPREQ0_SURF0_TTU_CNTL1, per_req / 2),
        (reg::HUBPREQ0_GLOBAL_TTU_CNTL, d.global_ttu),
        (reg::HUBPREQ0_EXPANSION_MODE, d.expansion),
        (reg::HUBP0_HUBPREQ_DEBUG, 1 << 26),
        (reg::HUBP0_HUBPREQ_DEBUG_DB, 1 << 8),
        (reg::CNVC0_SURFACE_PIXEL_FORMAT, 8),
        (reg::CNVC0_FORMAT_CONTROL, 0x2400_0101),
        (reg::DSCL0_SCL_MODE, 0),
        (reg::DSCL0_SCL_TAP_CONTROL, 0),
        (reg::DSCL0_RECOUT_START, (place.at.1 << 16) | place.at.0),
        (reg::DSCL0_RECOUT_SIZE, size),
        (reg::DSCL0_MPC_SIZE, screen),
        (reg::DSCL0_LB_DATA_FORMAT, 0x10),
        (reg::DSCL0_LB_MEMORY_CTRL, 0x0808_3F00),
        (reg::DSCL0_OBUF_CONTROL, 0xE0),
        (reg::DSCL0_2TAP_CONTROL, 0x0100_0100),
    ]
    .map(|(r, v)| (on_pipe(r, place.pipe), v))
}

/// The scaler's filters at their start (1.0, `dpp1_dscl_set_scl_filter`
/// without scaling).
const FILTER_INIT: [(u32, u32); 2] =
    [(reg::DSCL0_HORZ_FILTER_INIT, 0x0100_0000), (reg::DSCL0_VERT_FILTER_INIT, 0x0100_0000)];

/// MPCC_CONTROL for a plane blended by its pixels' (premultiplied)
/// alpha, and for one whose top byte means nothing (XRGB: blended by the
/// global alpha, `MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA`, not premultiplied;
/// dcn20_hwseq.c, `dcn20_update_mpcc`): top layer only, the background at
/// 10 bits, global alpha and gain FFh.
pub const MPCC_CONTROL_PER_PIXEL_ALPHA: u32 = 0xFFFF_0442;
pub const MPCC_CONTROL_GLOBAL_ALPHA: u32 = 0xFFFF_0422;

/// MPCC0 (segment 3) linking DPP0 to OPP0 (mpc/dcn10/dcn10_mpc.c,
/// `mpc1_insert_plane`: no bottom layer, top layer only (mode 2), the top
/// input DPP0, OPP0, the update lock mapped to OPP0's;
/// `mpc2_update_blending` for an opaque plane: per-pixel alpha,
/// premultiplied, global alpha and gain FFh, gains 1.0). Without it the
/// pipe has no OTG to take its updates from: its double-buffered settings
/// stay pending and HUBP stays in blank.
pub const MPC_TREE: [(u32, u32); 8] = [
    (reg::MPCC0_BOT_SEL, 0xF),
    (reg::MPCC0_CONTROL, MPCC_CONTROL_PER_PIXEL_ALPHA),
    (reg::MPCC0_TOP_SEL, 0),
    (reg::MPCC0_OPP_ID, 0),
    (reg::MPCC0_UPDATE_LOCK_SEL, 0),
    (reg::MPCC0_TOP_GAIN, 0x1_F000),
    (reg::MPCC0_BOT_GAIN_INSIDE, 0x1_F000),
    (reg::MPCC0_BOT_GAIN_OUTSIDE, 0x1_F000),
];

/// What the plane did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    /// `DCHUBP_CNTL` (out of blank, the underflow status).
    pub hubp: u32,
    /// Whether the surface's address latched.
    pub flipped: bool,
}

/// Show `s` on OTG0's lit link through pipe 0: the return buffer split
/// (`dcn31_program_compbuf_size`, then `dcn31_program_det_size`: the
/// compressed buffer 13 of the 16 64 KiB segments, fewer if another
/// pipe's DET holds some, pipe 0's DET 3, each waited for), the plane's registers, MPCC0, then HUBP unblanked and the
/// pattern generator off.
pub fn show(dev: &mut impl Dev, b: Bases, t: &Timing, s: Surface, ap: Aperture) -> Result<Shown, Error> {
    let mut io = Io { dev, b };
    // What the other pipes' DETs still hold (an overlay's, left by an
    // earlier driver: a pipe that is off never takes a new size) stays
    // theirs; the compressed buffer gets the rest of the 16 segments.
    let others: u32 = (1..4).map(|n| (io.r2(reg::DET0_CTRL + n) >> 8) & 7).sum();
    let compbuf = (16 - 3 - others).min(13);
    io.u2(reg::COMPBUF_CTRL, 0x1F, compbuf);
    if !io.until2(reg::COMPBUF_CTRL, 10_000, |v| (v >> 8) & 0x1F == compbuf) {
        return Err(Error::Stuck("compressed buffer"));
    }
    for (r, v) in plane_registers(t, s, ap).into_iter().chain(FILTER_INIT) {
        io.w2(r, v);
    }
    for (r, v) in MPC_TREE {
        io.w3(r, v);
    }
    if !s.alpha {
        io.w3(reg::MPCC0_CONTROL, MPCC_CONTROL_GLOBAL_ALPHA);
    }
    let mux = io.dev.read(b.dcn3 + reg::MPC_OUT0_MUX);
    io.w3(reg::MPC_OUT0_MUX, mux & !0xF);
    // The DET's size takes at the pipe's next update, once MPCC0 links it
    // to OTG0: written now, waited for after unblanking.
    io.w2(reg::DET0_CTRL, 3);
    io.u2(reg::HUBP0_DCHUBP_CNTL, 1, 0);
    io.u2(reg::DPG0_CONTROL, 1, 0);
    if !io.until2(reg::DET0_CTRL, 100_000, |v| (v >> 8) & 7 == 3) {
        return Err(Error::Stuck("DET"));
    }
    let flipped = io.until2(reg::HUBPREQ0_FLIP_CONTROL, 100_000, |v| v & (1 << 8) == 0);
    Ok(Shown { hubp: io.r2(reg::HUBP0_DCHUBP_CNTL), flipped })
}

/// MPCC_CONTROL for a plane blended over the one below it (MPCC_MODE 3,
/// top and bottom blending, as `mpc1_insert_plane` sets it for an MPCC
/// with a bottom), by its pixels' premultiplied alpha or opaque.
pub const MPCC_OVER_PER_PIXEL_ALPHA: u32 = MPCC_CONTROL_PER_PIXEL_ALPHA | 1;
pub const MPCC_OVER_GLOBAL_ALPHA: u32 = MPCC_CONTROL_GLOBAL_ALPHA | 1;

/// The compressed buffer's segments with an overlay: three fewer than
/// with pipe 0 alone, for the overlay's DET (dcn315_resource.c keeps
/// three segments in it free for a second plane).
const COMPBUF_WITH_OVERLAY: u32 = 10;

/// What an overlay did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overlaid {
    /// Its `DCHUBP_CNTL` (out of blank, the underflow status).
    pub hubp: u32,
    /// Its MPCC's status (MPCC_BUSY: blending).
    pub mpcc: u32,
    /// Whether its surface's address latched.
    pub flipped: bool,
}

impl<D: Card> Io<'_, D> {
    /// OTG0's master update lock (optc/dcn10/dcn10_optc.c, `optc1_lock`
    /// and `_unlock`: while it is held, the pipes' double-buffered
    /// settings wait, so that what is written between takes in one frame;
    /// UPDATE_LOCK_STATUS says it is held).
    fn lock(&mut self, on: bool) {
        self.w2(reg::OTG0_MASTER_UPDATE_LOCK, u32::from(on));
        if on {
            self.until2(reg::OTG0_MASTER_UPDATE_LOCK, 10, |v| v & (1 << 8) != 0);
        }
    }

    /// Pipe `p.pipe`'s plane and its MPCC above MPCC0, OPP0's tree's top.
    fn place(&mut self, t: &Timing, s: Surface, ap: Aperture, p: Place) {
        for (r, v) in placed_registers(t, s, ap, p).into_iter().chain(FILTER_INIT.map(|(r, v)| (on_pipe(r, p.pipe), v)))
        {
            self.w2(r, v);
        }
        let m = reg::MPCC_STRIDE * p.pipe;
        let blend = if s.alpha { MPCC_OVER_PER_PIXEL_ALPHA } else { MPCC_OVER_GLOBAL_ALPHA };
        for (r, v) in MPC_TREE {
            let v = match r {
                reg::MPCC0_BOT_SEL => 0,
                reg::MPCC0_CONTROL => blend,
                reg::MPCC0_TOP_SEL => p.pipe,
                _ => v,
            };
            self.w3(r + m, v);
        }
        let mux = self.r3(reg::MPC_OUT0_MUX);
        self.w3(reg::MPC_OUT0_MUX, (mux & !0xF) | p.pipe);
    }
}

/// Show `s` over pipe 0's plane through pipe `p.pipe` (1 to 3), as DC
/// adds a second plane (multi-plane overlay):
/// - the pipe powered and clocked, its HUBP blank on OTG0, as [`light`]
///   does pipe 0 (`dcn31_hubp_pg_control`, `dccg31_update_dpp_dto`,
///   `hubp2_clk_cntl`);
/// - the compressed buffer three segments smaller, then the pipe's DET
///   three, the order `dcn31_program_compbuf_size` keeps (the buffer
///   shrinks before a DET grows);
/// - under OTG0's lock: the plane's registers at its place, its MPCC
///   above MPCC0 in OPP0's tree (`mpc1_insert_plane`: MPCC0 its bottom,
///   blended top over bottom; the tree's top, MPC_OUT0_MUX, the new
///   MPCC), its DET, HUBP out of blank.
pub fn overlay(
    dev: &mut impl Card,
    b: Bases,
    t: &Timing,
    s: Surface,
    ap: Aperture,
    p: Place,
) -> Result<Overlaid, Error> {
    let n = p.pipe;
    if !(1..4).contains(&n) {
        return Err(Error::Stuck("no such pipe"));
    }
    let mut io = Io { dev, b };
    let ip = io.r2(reg::DC_IP_REQUEST_CNTL) & 1;
    io.w2(reg::DC_IP_REQUEST_CNTL, 1);
    io.u2(reg::DOMAIN0_PG_CONFIG + 2 * n, 1 << 8, 0);
    let powered = io.until2(reg::DOMAIN0_PG_STATUS + 2 * n, 1000, |v| v & (3 << 30) == 0);
    io.w2(reg::DC_IP_REQUEST_CNTL, ip);
    if !powered {
        return Err(Error::Stuck("pipe power"));
    }
    io.w1(reg::DPPCLK0_DTO_PARAM + n, 0x00FF_00FF);
    io.u1(reg::DPPCLK_DTO_CTRL, 0, 1 << (4 * n));
    io.u2(on_pipe(reg::DPP_TOP0_DPP_CONTROL, n), 0, 1 << 4);
    io.u2(on_pipe(reg::HUBP0_CLK_CNTL, n), 0, 1);
    io.u2(on_pipe(reg::HUBP0_DCHUBP_CNTL, n), 0xF0 | (1 << 12), 1);
    if io.r2(reg::COMPBUF_CTRL) & 0x1F > COMPBUF_WITH_OVERLAY {
        io.u2(reg::COMPBUF_CTRL, 0x1F, COMPBUF_WITH_OVERLAY);
        if !io.until2(reg::COMPBUF_CTRL, 10_000, |v| (v >> 8) & 0x1F == COMPBUF_WITH_OVERLAY) {
            return Err(Error::Stuck("compressed buffer"));
        }
    }
    io.lock(true);
    io.place(t, s, ap, p);
    io.w2(reg::DET0_CTRL + n, 3);
    io.u2(on_pipe(reg::HUBP0_DCHUBP_CNTL, n), 1, 0);
    io.lock(false);
    if !io.until2(reg::DET0_CTRL + n, 100_000, |v| (v >> 8) & 7 == 3) {
        return Err(Error::Stuck("DET"));
    }
    let flipped = io.until2(on_pipe(reg::HUBPREQ0_FLIP_CONTROL, n), 100_000, |v| v & (1 << 8) == 0);
    let mpcc = io.r3(reg::MPCC0_STATUS + reg::MPCC_STRIDE * n);
    Ok(Overlaid { hubp: io.r2(on_pipe(reg::HUBP0_DCHUBP_CNTL, n)), mpcc, flipped })
}

/// Move the overlay [`overlay`] showed to `p` (or show another surface
/// there), in one frame: its registers again under OTG0's lock.
pub fn move_overlay(dev: &mut impl Card, b: Bases, t: &Timing, s: Surface, ap: Aperture, p: Place) {
    let mut io = Io { dev, b };
    io.lock(true);
    io.place(t, s, ap, p);
    io.lock(false);
}

/// Take pipe `pipe`'s overlay off the screen (`mpc1_remove_mpcc`: MPCC0
/// the tree's top again, the MPCC's inputs, bottom and OPP none; once it
/// is idle, HUBP blank). The pipe stays powered.
pub fn overlay_off(dev: &mut impl Card, b: Bases, pipe: u32) {
    let mut io = Io { dev, b };
    let m = reg::MPCC_STRIDE * pipe;
    io.lock(true);
    let mux = io.r3(reg::MPC_OUT0_MUX);
    io.w3(reg::MPC_OUT0_MUX, mux & !0xF);
    for r in [reg::MPCC0_TOP_SEL, reg::MPCC0_BOT_SEL, reg::MPCC0_OPP_ID] {
        io.w3(r + m, 0xF);
    }
    io.lock(false);
    for _ in 0..100_000 {
        if io.r3(reg::MPCC0_STATUS + m) & 1 != 0 {
            break;
        }
        io.dev.delay_us(1);
    }
    io.u2(on_pipe(reg::HUBP0_DCHUBP_CNTL, pipe), 0, 1);
}

/// Switch `l` off as amdgpu does when it lets the card go (amdgpu_dm.c,
/// `dm_hw_fini`): OTG0 stopped, the link off and every PHY PLL down
/// through DMCUB, DMCUB stopped.
pub fn switch_off(dev: &mut impl Dev, b: Bases, ring: u64, l: Link) -> Result<(), Error> {
    let mut io = Io { dev, b };
    io.u2(otg::reg::CONTROL, 1, 0);
    io.until2(otg::reg::CONTROL, 100_000, |v| v & (1 << 16) == 0);
    let off = dmub::transmitter(l.phy, vbios::TRANSMITTER_DISABLE, vbios::MODE_DVI, 0, 0, l.hpd, l.connector);
    let mut r = io.send(ring, &off, "link off");
    for pll in vbios::COMBOPHY_PLL0..vbios::COMBOPHY_PLL0 + 5 {
        r = r.and_then(|()| io.send(ring, &dmub::pll_off(pll), "PLL off"));
    }
    dmub::stop(io.dev, b.dcn2);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    const B: Bases = Bases { dcn1: 0xC0, dcn2: 0x34C0, dcn3: 0x9000, mp0: 0x16000, nbio0: 0 };
    const RING: u64 = 0xF4_0100_0000 + 0xE_5400;
    const LINK: Link = Link { phy: 0, connector: 0x0C, encoder: 0x1E, hpd: 1 };

    /// CTA-861's 1920x1080 at 60 Hz, as the VG278's EDID gives it.
    const P1080: Timing = Timing {
        clock_khz: 148_500,
        hactive: 1920,
        hsync_start: 2008,
        hsync_end: 2052,
        htotal: 2200,
        vactive: 1080,
        vsync_start: 1084,
        vsync_end: 1089,
        vtotal: 1125,
        hsync_positive: true,
        vsync_positive: true,
    };

    /// The display engine as far as these steps see it: registers that
    /// answer as the hardware does (clocks on, power domains up, buffers
    /// resized, DMCUB and the SMU taking what they're given), the
    /// commands DMCUB took.
    #[derive(Default)]
    struct Dcn {
        r: BTreeMap<u32, u32>,
        mem: BTreeMap<u64, [u8; 64]>,
        commands: Vec<[u8; 64]>,
        writes: Vec<(u32, u32)>,
        smu: Vec<(u32, u32)>,
    }

    impl Dcn {
        fn get(&self, r: u32) -> u32 {
            self.r.get(&r).copied().unwrap_or(0)
        }
        /// Each command's type, sub type and first two payload bytes.
        fn kinds(&self) -> Vec<(u8, u8, u8, u8)> {
            self.commands.iter().map(|c| (c[0], c[1], c[4], c[5])).collect()
        }
    }

    impl Card for Dcn {
        fn read(&mut self, r: u32) -> u32 {
            let v = self.get(r);
            let s2 = r.wrapping_sub(B.dcn2);
            match s2 {
                // The clocks say they're on once enabled.
                reg::OPTC0_INPUT_CLOCK_CONTROL if v & 2 != 0 => v | 4,
                reg::OTG0_CLOCK_CONTROL if v & 1 != 0 => v | (1 << 8),
                // The OTG's state follows its enable.
                otg::reg::CONTROL => (v & !(1 << 16)) | ((v & 1) << 16),
                // A pipe's domain is on once its gate is off.
                0x81 | 0x83 | 0x85 | 0x87 => {
                    if self.get(r - 1) & (1 << 8) != 0 {
                        2 << 30
                    } else {
                        0
                    }
                }
                // Buffers take their sizes.
                reg::COMPBUF_CTRL => (v & !0x1F00) | ((v & 0x1F) << 8),
                0x4CC..=0x4CF => (v & !0x700) | ((v & 7) << 8),
                // The flip happens.
                _ if (0..4).any(|n| s2 == on_pipe(reg::HUBPREQ0_FLIP_CONTROL, n)) => v & !(1 << 8),
                // The lock says it is held.
                reg::OTG0_MASTER_UPDATE_LOCK => (v & 1) | ((v & 1) << 8),
                // The SMU answers at once.
                _ if r == B.mp0 + reg::MP1_C2PMSG_38 && v == 0 => smu::OK,
                _ => v,
            }
        }
        fn write(&mut self, r: u32, v: u32) {
            self.r.insert(r, v);
            self.writes.push((r, v));
            // A command, unless the write pointer is being reset (these
            // tests send too few commands to wrap the ring to 0).
            if r == B.dcn2 + dmub::reg::INBOX1_WPTR && v != 0 {
                let at = RING + u64::from(v.wrapping_sub(64) % dmub::RB_SIZE);
                self.commands.push(self.mem[&at]);
                self.r.insert(B.dcn2 + dmub::reg::INBOX1_RPTR, v);
            }
            if r == B.nbio0 + reg::PCIE_DATA2 {
                let param = self.get(B.mp0 + reg::MP1_C2PMSG_37);
                self.smu.push((v, param));
                self.r.insert(B.mp0 + reg::MP1_C2PMSG_38, 0);
            }
        }
        fn delay_us(&mut self, _: u32) {}
    }

    impl Memory for Dcn {
        fn put(&mut self, gpu: u64, data: &[u8]) {
            let mut c = [0u8; 64];
            c[..data.len()].copy_from_slice(data);
            self.mem.insert(gpu, c);
        }
        fn get32(&mut self, _: u64) -> u32 {
            0
        }
        fn flush(&mut self) {}
    }

    /// The init and the lit link's DMCUB commands, in amdgpu's order on
    /// the reference PC (its inbox ring: power gating INIT and DISABLE for four
    /// pipes, D0, save init; then for a mode, the link off, five PLLs off,
    /// the pixel clock, encoder setup, the link on).
    #[test]
    fn dmcub_commands_in_amdgpus_order() {
        let mut d = Dcn::default();
        assert_eq!(init(&mut d, B, RING), 7);
        assert_eq!(
            d.kinds(),
            [
                (128, 3, 0, vbios::INIT),
                (128, 3, 0, 0),
                (128, 3, 1, 0),
                (128, 3, 2, 0),
                (128, 3, 3, 0),
                (72, 3, dmub::idle::D0, 0),
                (72, 1, 0, 0)
            ]
        );
        let mut d = Dcn::default();
        let lit = light(&mut d, B, RING, LINK, &P1080).unwrap();
        let subs: Vec<u8> = d.commands.iter().map(|c| c[1]).collect();
        assert_eq!(subs, [1, 1, 2, 2, 2, 2, 2, 2, 0, 1]);
        // INIT, then DISABLE, then ENABLE for PHY A.
        assert_eq!([d.commands[0][5], d.commands[1][5], d.commands[9][5]], [7, 0, 1]);
        // The pixel clock is amdgpu's command byte for byte.
        assert_eq!(&d.commands[7][..20], &dmub::pixel_clock(1_485_000, 20, 0x1E, 3, 0, 0, 0)[..20]);
        assert_eq!(d.smu, [(smu::SET_DISPLAY_IDLE_OPTIMIZATIONS, 0)]);
        assert_eq!(lit.dig_fifo, 0);
    }

    /// The lit link's registers as amdgpu leaves them for 1080p60.
    #[test]
    fn lights_as_amdgpu_does() {
        let mut d = Dcn::default();
        light(&mut d, B, RING, LINK, &P1080).unwrap();
        let s2 = |r| d.get(B.dcn2 + r);
        assert_eq!(s2(otg::reg::H_TOTAL), 0x897);
        assert_eq!(s2(reg::OTG0_VSTARTUP_PARAM), 0x2C);
        assert_eq!(s2(reg::OTG0_VUPDATE_PARAM), 0x00FB_0226);
        assert_eq!(s2(reg::OTG0_VREADY_PARAM), 0x14D);
        // VTG0: on, VCOUNT_INIT 461h, FP2 2 (amdgpu's 8461_0002h).
        assert_eq!(s2(reg::VTG0_CONTROL), 0x8461_0002);
        assert_eq!(s2(otg::reg::CONTROL) & 0x301, 0x201);
        assert_eq!(s2(reg::DIG0_BE_CNTL), 0x0003_0100);
        assert_eq!(s2(reg::DIG0_HDMI_GC) & 1, 0);
        assert_eq!(d.get(B.dcn1 + reg::DPPCLK0_DTO_PARAM), 0x00FF_00FF);
        assert_eq!(d.get(B.dcn1 + reg::DPPCLK_DTO_CTRL) & 1, 1);
        // The pattern: colour squares at the mode's size.
        assert_eq!(s2(reg::DPG0_DIMENSIONS), (1920 << 16) | 1080);
        assert_eq!(s2(reg::DPG0_CONTROL) & 0x00FF_3171, 0x0066_1001);
    }

    /// The plane's computed registers are amdgpu's at 1080p60 where they
    /// don't depend on the surface (amdgpu's is tiled and 10-bit).
    #[test]
    fn plane_registers_as_amdgpu_computes_them() {
        let s = Surface { address: 0xF4_0400_0000, pitch: 1920, alpha: true };
        let ap = Aperture { base: 0xF4_0000_0000, size: 512 << 20 };
        let r: BTreeMap<u32, u32> = plane_registers(&P1080, s, ap).into_iter().collect();
        for (reg, v) in [
            (reg::HUBP0_PRI_VIEWPORT_DIMENSION, 0x0438_0780),
            (reg::HUBPREQ0_SURFACE_PITCH, 0x77F),
            (reg::HUBPREQ0_SYSTEM_APERTURE_LOW, 0x003D_0000),
            (reg::HUBPREQ0_SYSTEM_APERTURE_HIGH, 0x003D_07FF),
            (reg::HUBPREQ0_L1_TLB_CNTL, 0x19),
            (reg::HUBPREQ0_BLANK_OFFSET_0, 0x0029_001F),
            (reg::HUBPREQ0_BLANK_OFFSET_1, 0x1184),
            (reg::HUBPREQ0_DST_DIMENSIONS, 0x0001_638E),
            (reg::HUBPREQ0_DST_AFTER_SCALER, 0x21),
            (reg::HUBPREQ0_REF_FREQ_TO_PIX_FREQ, 0x0001_4AFD),
            (reg::HUBPREQ0_PER_LINE_DELIVERY, 0x136),
            (reg::HUBPREQ0_SURF0_TTU_CNTL0, 0x0800_052B),
            (reg::DSCL0_RECOUT_SIZE, 0x0438_0780),
            (reg::DSCL0_MPC_SIZE, 0x0438_0780),
            (reg::DSCL0_LB_MEMORY_CTRL, 0x0808_3F00),
        ] {
            assert_eq!(r[&reg], v, "register {reg:#x}");
        }
        // Linear ARGB8888 at Slate's address, high half before low.
        assert_eq!((r[&reg::HUBP0_SURFACE_CONFIG], r[&reg::HUBP0_TILING_CONFIG]), (8, 0));
        let order: Vec<u32> = plane_registers(&P1080, s, ap).iter().map(|(r, _)| *r).collect();
        let hi = order.iter().position(|&x| x == reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS_HIGH);
        let lo = order.iter().position(|&x| x == reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS);
        assert!(hi < lo);
        assert_eq!(
            (r[&reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS_HIGH], r[&reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS]),
            (0xF4, 0x0400_0000)
        );
    }

    #[test]
    fn shows_a_plane() {
        let mut d = Dcn::default();
        light(&mut d, B, RING, LINK, &P1080).unwrap();
        let s = Surface { address: 0xF4_0400_0000, pitch: 1920, alpha: true };
        let ap = Aperture { base: 0xF4_0000_0000, size: 512 << 20 };
        let shown = show(&mut d, B, &P1080, s, ap).unwrap();
        assert!(shown.flipped);
        assert_eq!(shown.hubp & 1, 0, "unblanked");
        assert_eq!(d.get(B.dcn2 + reg::DPG0_CONTROL) & 1, 0, "the pattern off");
        assert_eq!(Card::read(&mut d, B.dcn2 + reg::DET0_CTRL), 0x303);
        assert_eq!(d.get(B.dcn2 + reg::COMPBUF_CTRL) & 0x1F, 13);
        // With an overlay's DET left by an earlier driver, the compressed
        // buffer takes what is left.
        let mut l = Dcn::default();
        light(&mut l, B, RING, LINK, &P1080).unwrap();
        l.r.insert(B.dcn2 + reg::DET1_CTRL, 0x303);
        show(&mut l, B, &P1080, s, ap).unwrap();
        assert_eq!(l.get(B.dcn2 + reg::COMPBUF_CTRL) & 0x1F, 10);
        // MPCC0 as amdgpu's: DPP0 into OPP0, top layer only.
        for (r, v) in MPC_TREE {
            assert_eq!(d.get(B.dcn3 + r), v);
        }
        // An XRGB surface blends by the global alpha.
        let mut x = Dcn::default();
        light(&mut x, B, RING, LINK, &P1080).unwrap();
        show(&mut x, B, &P1080, Surface { alpha: false, ..s }, ap).unwrap();
        assert_eq!(x.get(B.dcn3 + reg::MPCC0_CONTROL), MPCC_CONTROL_GLOBAL_ALPHA);
        // The compressed buffer shrinks before the DET grows.
        let compbuf = d.writes.iter().position(|&(r, _)| r == B.dcn2 + reg::COMPBUF_CTRL).unwrap();
        let det = d.writes.iter().position(|&(r, _)| r == B.dcn2 + reg::DET0_CTRL).unwrap();
        assert!(compbuf < det);
    }

    /// Pipe `n`'s register `r` as DCN 3.1.5's header names it.
    #[test]
    fn pipes_registers_as_the_header_has_them() {
        // dcn_3_1_5_offset.h: HUBP1_DCSURF_SURFACE_CONFIG, HUBPREQ1's
        // primary surface address and flip control, HUBP1_DCHUBP_CNTL,
        // HUBP2_DCHUBP_CNTL, DPP_TOP1 and 2, CNVC_CFG1's pixel format,
        // DSCL1_RECOUT_START, CNVC_CUR1 (CUR0's on pipe 1).
        for (r, n, at) in [
            (reg::HUBP0_SURFACE_CONFIG, 1, 0x6C1),
            (reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS, 1, 0x6E6),
            (reg::HUBPREQ0_FLIP_CONTROL, 1, 0x6F7),
            (reg::HUBP0_DCHUBP_CNTL, 1, 0x6CF),
            (reg::HUBP0_DCHUBP_CNTL, 2, 0x7AB),
            (reg::DPP_TOP0_DPP_CONTROL, 1, 0xE30),
            (reg::DPP_TOP0_DPP_CONTROL, 2, 0xF9B),
            (reg::CNVC0_SURFACE_PIXEL_FORMAT, 1, 0xE3A),
            (reg::DSCL0_RECOUT_START, 1, 0xE7C),
            (reg::OTG0_STATUS, 1, reg::OTG0_STATUS),
        ] {
            assert_eq!(on_pipe(r, n), at, "{r:#x} on pipe {n}");
        }
    }

    #[test]
    fn overlays_a_plane() {
        let mut d = Dcn::default();
        light(&mut d, B, RING, LINK, &P1080).unwrap();
        let ap = Aperture { base: 0xF4_0000_0000, size: 512 << 20 };
        let s = Surface { address: 0xF4_0400_0000, pitch: 1920, alpha: false };
        show(&mut d, B, &P1080, s, ap).unwrap();
        let at = d.writes.len();
        let o = Surface { address: 0xF4_0880_0000, pitch: 1920, alpha: true };
        let p = Place { pipe: 1, at: (100, 200), size: (640, 480) };
        let shown = overlay(&mut d, B, &P1080, o, ap, p).unwrap();
        assert!(shown.flipped);
        assert_eq!(shown.hubp & 1, 0, "unblanked");
        let g = |r: u32| d.get(B.dcn2 + r);
        assert_eq!(g(0x82) & (1 << 8), 0, "pipe 1 powered");
        assert_eq!(d.get(B.dcn1 + reg::DPPCLK1_DTO_PARAM), 0x00FF_00FF);
        assert_eq!(d.get(B.dcn1 + reg::DPPCLK_DTO_CTRL) & 0x11, 0x11);
        assert_eq!(g(0x6CF) & 0xF0, 0, "HUBP1 on OTG0");
        // The plane: its address, viewport, recout and the screen's MPC size.
        assert_eq!(g(0x6E6), 0x0880_0000);
        assert_eq!(g(on_pipe(reg::HUBP0_PRI_VIEWPORT_DIMENSION, 1)), (480 << 16) | 640);
        assert_eq!(g(0xE7C), (200 << 16) | 100);
        assert_eq!(g(on_pipe(reg::DSCL0_RECOUT_SIZE, 1)), (480 << 16) | 640);
        assert_eq!(g(on_pipe(reg::DSCL0_MPC_SIZE, 1)), (1080 << 16) | 1920);
        // A line's delivery: 640 pixels at 148.5 MHz in 24 MHz cycles.
        assert_eq!(g(on_pipe(reg::HUBPREQ0_PER_LINE_DELIVERY, 1)), 640 * 24_000 / 148_500);
        // Pipe 0's plane is as it was.
        assert_eq!(g(reg::DSCL0_RECOUT_START), 0);
        assert_eq!(g(reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS), 0x0400_0000);
        // MPCC1 above MPCC0, blending by alpha; the tree's top MPCC1.
        let m = |d: &Dcn, r: u32| d.get(B.dcn3 + reg::MPCC_STRIDE + r);
        assert_eq!((m(&d, reg::MPCC0_TOP_SEL), m(&d, reg::MPCC0_BOT_SEL), m(&d, reg::MPCC0_OPP_ID)), (1, 0, 0));
        assert_eq!(m(&d, reg::MPCC0_CONTROL), MPCC_OVER_PER_PIXEL_ALPHA);
        assert_eq!(MPCC_OVER_PER_PIXEL_ALPHA & 3, 3, "top and bottom blending");
        assert_eq!(d.get(B.dcn3 + reg::MPC_OUT0_MUX) & 0xF, 1);
        assert_eq!(d.get(B.dcn3 + reg::MPCC0_BOT_SEL), 0xF, "MPCC0 still the bottom");
        // The compressed buffer shrinks before pipe 1's DET grows; the
        // plane goes in under OTG0's lock.
        let new = &d.writes[at..];
        // The first write to `r` whose low bits are `v` (any, if none).
        let pos = |r: u32, v: Option<u32>| {
            new.iter().position(|&(w, x)| w == B.dcn2 + r && v.is_none_or(|v| x & 0xFF == v)).unwrap()
        };
        assert!(pos(reg::COMPBUF_CTRL, Some(COMPBUF_WITH_OVERLAY)) < pos(reg::DET1_CTRL, Some(3)));
        let (locked, unlocked) =
            (pos(reg::OTG0_MASTER_UPDATE_LOCK, Some(1)), pos(reg::OTG0_MASTER_UPDATE_LOCK, Some(0)));
        assert!(locked < pos(0x6E6, None) && pos(0x6E6, None) < unlocked);
        assert!(locked < pos(reg::DET1_CTRL, Some(3)) && pos(reg::DET1_CTRL, Some(3)) < unlocked);

        // Moved: the new place, in one frame.
        let at = d.writes.len();
        move_overlay(&mut d, B, &P1080, o, ap, Place { at: (0, 0), ..p });
        assert_eq!(d.get(B.dcn2 + 0xE7C), 0);
        assert_eq!(d.writes[at], (B.dcn2 + reg::OTG0_MASTER_UPDATE_LOCK, 1));
        assert_eq!(*d.writes.last().unwrap(), (B.dcn2 + reg::OTG0_MASTER_UPDATE_LOCK, 0));

        // Off: MPCC0 the top again, MPCC1 out of the tree, HUBP1 blank.
        overlay_off(&mut d, B, 1);
        assert_eq!(d.get(B.dcn3 + reg::MPC_OUT0_MUX) & 0xF, 0);
        assert_eq!(m(&d, reg::MPCC0_TOP_SEL), 0xF);
        assert_eq!(m(&d, reg::MPCC0_BOT_SEL), 0xF);
        assert_eq!(d.get(B.dcn2 + 0x6CF) & 1, 1);
        // Pipe 0 is never a pipe for overlays.
        assert!(overlay(&mut d, B, &P1080, o, ap, Place { pipe: 0, ..p }).is_err());
    }

    #[test]
    fn switches_off_and_says_what_failed() {
        let mut d = Dcn::default();
        light(&mut d, B, RING, LINK, &P1080).unwrap();
        let before = d.commands.len();
        switch_off(&mut d, B, RING, LINK).unwrap();
        let subs: Vec<u8> = d.commands[before..].iter().map(|c| c[1]).collect();
        assert_eq!(subs, [1, 2, 2, 2, 2, 2]);
        assert_eq!(d.get(B.dcn2 + otg::reg::CONTROL) & 1, 0);
        // A timing the OTG can't hold.
        let bad = Timing { hsync_start: 1000, ..P1080 };
        assert_eq!(light(&mut Dcn::default(), B, RING, LINK, &bad), Err(Error::Timing));
    }

    /// From amdgpu's dump in target/ when it is there: the computed
    /// registers that don't depend on the surface.
    #[test]
    fn refpc_dump() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/dcn315-hdmi-1080p60.txt");
        let Ok(dump) = std::fs::read_to_string(path) else { return };
        let have = |name: &str| {
            let key = std::format!("dcn315.reg{name} => ");
            let line = dump.lines().find(|l| l.starts_with(&key)).unwrap();
            u32::from_str_radix(line[key.len()..].trim_start_matches("0x"), 16).unwrap()
        };
        let s = Surface { address: 0xF4_1B00_0000, pitch: 1920, alpha: true };
        let ap = Aperture { base: 0xF4_0000_0000, size: 512 << 20 };
        let r: BTreeMap<u32, u32> = plane_registers(&P1080, s, ap).into_iter().collect();
        for (reg, name) in [
            (reg::HUBPREQ0_BLANK_OFFSET_0, "HUBPREQ0_BLANK_OFFSET_0"),
            (reg::HUBPREQ0_BLANK_OFFSET_1, "HUBPREQ0_BLANK_OFFSET_1"),
            (reg::HUBPREQ0_DST_DIMENSIONS, "HUBPREQ0_DST_DIMENSIONS"),
            (reg::HUBPREQ0_REF_FREQ_TO_PIX_FREQ, "HUBPREQ0_REF_FREQ_TO_PIX_FREQ"),
            (reg::HUBPREQ0_PER_LINE_DELIVERY, "HUBPREQ0_PER_LINE_DELIVERY"),
            (reg::HUBPREQ0_DST_AFTER_SCALER, "HUBPREQ0_DST_AFTER_SCALER"),
            (reg::HUBPREQ0_PRIMARY_SURFACE_ADDRESS, "HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS"),
            (reg::HUBPREQ0_SYSTEM_APERTURE_LOW, "HUBPREQ0_DCN_VM_SYSTEM_APERTURE_LOW_ADDR"),
            (reg::DSCL0_RECOUT_SIZE, "DSCL0_RECOUT_SIZE"),
        ] {
            assert_eq!(r[&reg], have(name), "{name}");
        }
        for (reg, v) in global_sync(&P1080) {
            let name = match reg {
                reg::OTG0_VSTARTUP_PARAM => "OTG0_OTG_VSTARTUP_PARAM",
                reg::OTG0_VUPDATE_PARAM => "OTG0_OTG_VUPDATE_PARAM",
                reg::OTG0_VREADY_PARAM => "OTG0_OTG_VREADY_PARAM",
                _ => "VTG0_CONTROL",
            };
            let want = if name == "VTG0_CONTROL" { have(name) & 0x7FFF_7FFF } else { have(name) };
            assert_eq!(v, want, "{name}");
        }
        for (reg, v) in MPC_TREE {
            let name = match reg {
                reg::MPCC0_BOT_SEL => "MPCC0_MPCC_BOT_SEL",
                reg::MPCC0_CONTROL => "MPCC0_MPCC_CONTROL",
                reg::MPCC0_TOP_SEL => "MPCC0_MPCC_TOP_SEL",
                reg::MPCC0_OPP_ID => "MPCC0_MPCC_OPP_ID",
                reg::MPCC0_UPDATE_LOCK_SEL => "MPCC0_MPCC_UPDATE_LOCK_SEL",
                reg::MPCC0_TOP_GAIN => "MPCC0_MPCC_TOP_GAIN",
                reg::MPCC0_BOT_GAIN_INSIDE => "MPCC0_MPCC_BOT_GAIN_INSIDE",
                _ => "MPCC0_MPCC_BOT_GAIN_OUTSIDE",
            };
            assert_eq!(v, have(name), "{name}");
        }
    }
}
