// SPDX-License-Identifier: MIT OR Apache-2.0

//! DMCUB, the display engine's microcontroller (ADR 0171, M32 phase 4,
//! step 6). On DCN 3.1 its firmware (AMD's `dcn_3_1_5_dmcub.bin`, from
//! linux-firmware) programs the PHYs and the pixel clock for the driver,
//! which sends it commands through a ring in the GPU's memory. This module
//! reads the firmware file, lays out its windows in the GPU's memory and
//! starts it the "back door" way: the driver copies the code itself and
//! points DMCUB's windows at it, without AMD's security processor.
//!
//! Facts from amdgpu and DC (Linux v7.2.12, read as documentation, ADR
//! 0157's addendum; Slate's own code):
//!
//! - The file (amdgpu_ucode.h, `common_firmware_header`,
//!   `dmcub_firmware_header_v1_0`): its version at 10h, the payload's
//!   offset at 18h, the instruction region's size at 20h and the data
//!   region's at 24h. The instruction region starts with a 256-byte PSP
//!   header and ends with a PSP footer of 256 bytes (or 512), which the
//!   back door leaves out (amdgpu_dm.c, `dm_dmub_sw_init`,
//!   `dm_dmub_hw_init`; dmub_srv.c, `dmub_srv_get_fw_meta_info_from_raw_fw`).
//! - Its metadata (dmub_cmd.h, `dmub_fw_meta_info`, 64 bytes, magic
//!   444D5542h "DMUB"): at the end of the instruction region, up to 15
//!   bytes before it, or 24h bytes before the end of a data region; it
//!   gives the sizes of the firmware state and trace buffer windows.
//! - The windows (dmub_srv.c, `dmub_srv_calc_region_info`): instruction
//!   code, the stack (128 KiB and a 512 KiB context), data, the VBIOS, the
//!   mailbox (two 8 KiB rings: `DMUB_RB_SIZE`, 64-byte commands, 128 of
//!   them, dmub_cmd.h), the trace buffer, the firmware state, scratch
//!   (1 KiB); each starts on 256 bytes and is rounded up to 64. DMCUB sees
//!   them at its own addresses (`DMUB_CW0_BASE` 6000_0000h, CW1
//!   6100_0000h, CW3 to CW6 6300_0000h to 6600_0000h, region 5
//!   A000_0000h).
//! - Starting it (dmub_dcn31.c, `dmub_dcn31_reset`, `_backdoor_load`,
//!   `_setup_windows`, `_setup_mailbox`, `_setup_out_mailbox`,
//!   `_setup_outbox0`, `_enable_dmub_boot_options`, `_reset_release`;
//!   dmub_srv.c, `dmub_srv_hw_init`, `dmub_srv_wait_for_auto_load`): stop
//!   a running firmware (GPINT command 2, answered with DEADDEADh in
//!   SCRATCH7), hold DMCUB in reset, set the code and stack windows (their
//!   offsets as system addresses: the GPU address less the FB base plus
//!   the FB offset), the other windows (GPU addresses), the rings, the
//!   boot options (SCRATCH14), release it, and wait for SCRATCH0's
//!   "DAL firmware" and "mailbox ready" bits.
//! - The registers: dcn_3_1_5_offset.h and dcn_3_1_5_sh_mask.h (DCN's
//!   segment 2), as below.
//! - Checked against the reference PC's registers under amdgpu (umr, 2026-10-28):
//!   with the same firmware and VBIOS, the windows from CW3 on, region 5
//!   and the rings come out as amdgpu left them.

use crate::interp::Card;

/// Segment 2 register words (dcn_3_1_5_offset.h).
pub mod reg {
    pub const CC_DC_PIPE_DIS: u32 = 0x0CA;
    pub const REGION4_OFFSET: u32 = 0x196;
    pub const REGION5_OFFSET: u32 = 0x198;
    pub const REGION5_OFFSET_HIGH: u32 = 0x199;
    pub const REGION5_TOP_ADDRESS: u32 = 0x1A2;
    /// CWn's base address is `CW_BASE + n`, its top `CW_TOP + n`, its
    /// offset `CW_OFFSET + 2n` (and the high half after it).
    pub const CW_BASE: u32 = 0x1A5;
    pub const CW_TOP: u32 = 0x1AD;
    pub const CW_OFFSET: u32 = 0x1B5;
    pub const SEC_CNTL: u32 = 0x1CE;
    pub const INBOX1_BASE_ADDRESS: u32 = 0x1D4;
    pub const INBOX1_SIZE: u32 = 0x1D5;
    pub const INBOX1_WPTR: u32 = 0x1D6;
    pub const INBOX1_RPTR: u32 = 0x1D7;
    pub const OUTBOX0_BASE_ADDRESS: u32 = 0x1D8;
    pub const OUTBOX0_SIZE: u32 = 0x1D9;
    pub const OUTBOX0_WPTR: u32 = 0x1DA;
    pub const OUTBOX0_RPTR: u32 = 0x1DB;
    pub const OUTBOX1_BASE_ADDRESS: u32 = 0x1DC;
    pub const OUTBOX1_SIZE: u32 = 0x1DD;
    pub const OUTBOX1_WPTR: u32 = 0x1DE;
    pub const OUTBOX1_RPTR: u32 = 0x1DF;
    pub const SCRATCH0: u32 = 0x1E3;
    pub const SCRATCH1: u32 = 0x1E4;
    pub const SCRATCH7: u32 = 0x1EA;
    pub const SCRATCH14: u32 = 0x1F1;
    pub const SCRATCH15: u32 = 0x1F2;
    pub const CNTL: u32 = 0x1F6;
    pub const GPINT_DATAIN1: u32 = 0x1F8;
    pub const TIMER_CURRENT: u32 = 0x1FD;
    pub const CNTL2: u32 = 0x200;
    pub const MMHUBBUB_SOFT_RESET: u32 = 0x342;
}

/// Fields (dcn_3_1_5_sh_mask.h).
const DC_DMCUB_ENABLE: u32 = 1 << 16;
const CNTL_ENABLE: u32 = 1 << 16;
const CNTL_TRACEPORT_EN: u32 = 1 << 19;
const CNTL_PWAIT_MODE_STATUS: u32 = 1 << 20;
const CNTL2_SOFT_RESET: u32 = 1;
const SEC_RESET: u32 = 1 << 16;
const SEC_MEM_UNIT_ID: u32 = 0x3F << 8;
const DMUIF_SOFT_RESET: u32 = 1 << 8;
const TOP_ADDRESS: u32 = 0x1FFF_FFFF;
const WINDOW_ENABLE: u32 = 1 << 31;

/// DMCUB's own addresses for its windows (dmub_srv.c).
const CW0_BASE: u32 = 0x6000_0000;
const CW1_BASE: u32 = 0x6100_0000;
const CW3_BASE: u32 = 0x6300_0000;
const CW4_BASE: u32 = 0x6400_0000;
const CW5_BASE: u32 = 0x6500_0000;
const CW6_BASE: u32 = 0x6600_0000;
const REGION5_BASE: u32 = 0xA000_0000;
/// The trace buffer's ring starts after its 16-byte header
/// (`TRACE_BUFFER_ENTRY_OFFSET`, dmub_cmd.h).
const TRACE_ENTRY_OFFSET: u32 = 16;

/// One ring: 128 commands of 64 bytes.
pub const RB_SIZE: u32 = 64 * 128;
const STACK_SIZE: u64 = (128 + 512) << 10;
const SCRATCH_SIZE: u64 = 1 << 10;

const META_MAGIC: u32 = 0x444D_5542;
const META_SIZE: usize = 64;
const META_LEGACY_OFFSET: usize = 0x24;
const PSP_HEADER: usize = 256;
const PSP_FOOTER: usize = 256;

/// GPINT (dmub_cmd.h, `dmub_gpint_data_register`: the parameter in 15:0,
/// the command in 27:16, the status bit at 28).
const GPINT_STOP_FW: u32 = 2;
const GPINT_STATUS: u32 = 1 << 28;
const STOP_FW_RESPONSE: u32 = 0xDEAD_DEAD;

/// SCRATCH0's boot status bits (dmub_cmd.h, `dmub_fw_boot_status`).
pub const STATUS_DAL_FW: u32 = 1;
pub const STATUS_MAILBOX_READY: u32 = 1 << 1;

/// SCRATCH14's boot options (dmub_cmd.h, `dmub_fw_boot_options`): bit 7,
/// `enable_dpia`, is what amdgpu sets on Raphael (it leaves 80h).
pub const OPTION_ENABLE_DPIA: u32 = 1 << 7;

/// What the metadata says, or the defaults without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub state_size: u32,
    pub trace_size: u32,
    pub version: u32,
    pub dal: bool,
}

impl Default for Meta {
    fn default() -> Self {
        // dmub_srv.c: `DMUB_FW_STATE_SIZE`, `DMUB_TRACE_BUFFER_SIZE`.
        Meta { state_size: 64 << 10, trace_size: 64 << 10, version: 0, dal: false }
    }
}

/// A DMCUB firmware file.
#[derive(Debug)]
pub struct Firmware<'a> {
    /// The version in its header (05003700h is 5.0.55.0).
    pub version: u32,
    /// The code and constants, without the PSP's header and footer.
    pub inst_const: &'a [u8],
    /// The instruction region as the PSP takes it (signed: its header
    /// and footer included; amdgpu_ucode.c, `AMDGPU_UCODE_ID_DMCUB`).
    pub signed: &'a [u8],
    /// The data region (empty in recent firmware).
    pub bss: &'a [u8],
    /// Its metadata, if it has any.
    pub meta: Option<Meta>,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The metadata `back` bytes before the end of `blob`.
fn meta_at(blob: &[u8], back: usize) -> Option<Meta> {
    let at = blob.len().checked_sub(back + META_SIZE)?;
    if u32_at(blob, at)? != META_MAGIC {
        return None;
    }
    Some(Meta {
        state_size: u32_at(blob, at + 4)?,
        trace_size: u32_at(blob, at + 8)?,
        version: u32_at(blob, at + 12)?,
        dal: *blob.get(at + 16)? != 0,
    })
}

impl<'a> Firmware<'a> {
    pub fn new(bin: &'a [u8]) -> Option<Self> {
        let version = u32_at(bin, 0x10)?;
        let payload = u32_at(bin, 0x18)? as usize;
        let inst = u32_at(bin, 0x20)? as usize;
        let bss = u32_at(bin, 0x24)? as usize;
        let region = bin.get(payload..payload.checked_add(inst)?)?;
        let bss = bin.get(payload + inst..payload + inst + bss)?;
        let code = region.get(PSP_HEADER..)?;
        if bss.len() > META_LEGACY_OFFSET + META_SIZE
            && let Some(meta) = meta_at(bss, META_LEGACY_OFFSET)
        {
            let inst_const = code.get(..code.len().checked_sub(PSP_FOOTER)?)?;
            return Some(Firmware { version, inst_const, signed: region, bss, meta: Some(meta) });
        }
        // A footer of 256 bytes, else 512; the metadata ends up to 15
        // bytes before the code's end.
        for footer in [PSP_FOOTER, 2 * PSP_FOOTER] {
            let Some(inst_const) = code.len().checked_sub(footer).and_then(|n| code.get(..n)) else { continue };
            if let Some(meta) = (0..16).find_map(|back| meta_at(inst_const, back)) {
                return Some(Firmware { version, inst_const, signed: region, bss, meta: Some(meta) });
            }
        }
        let inst_const = code.get(..code.len().checked_sub(PSP_FOOTER)?)?;
        Some(Firmware { version, inst_const, signed: region, bss, meta: None })
    }
}

/// A window: where it is in the driver's block of GPU memory, its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub at: u64,
    pub size: u64,
}

pub const INST: usize = 0;
pub const STACK: usize = 1;
pub const BSS: usize = 2;
pub const VBIOS: usize = 3;
pub const MAILBOX: usize = 4;
pub const TRACE: usize = 5;
pub const STATE: usize = 6;
pub const SCRATCH: usize = 7;

/// The windows in one block of GPU memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub windows: [Window; 8],
    /// The block's size (whole 4 KiB pages).
    pub size: u64,
}

const fn align(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

impl Layout {
    pub fn new(fw: &Firmware, vbios_len: usize) -> Self {
        let meta = fw.meta.unwrap_or_default();
        let sizes = [
            fw.inst_const.len() as u64,
            STACK_SIZE,
            fw.bss.len() as u64,
            vbios_len as u64,
            2 * u64::from(RB_SIZE),
            u64::from(meta.trace_size),
            u64::from(meta.state_size),
            SCRATCH_SIZE,
        ];
        let mut windows = [Window { at: 0, size: 0 }; 8];
        let mut top = 0;
        for (w, size) in windows.iter_mut().zip(sizes) {
            let at = align(top, 256);
            *w = Window { at, size: align(size, 64) };
            top = at + w.size;
        }
        Layout { windows, size: align(top, 4096) }
    }
}

/// Where the block is: its GPU address and its system address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub gpu: u64,
    pub system: u64,
}

/// How DMCUB's code gets into its windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    /// The driver copied it in and sets the code and stack windows.
    BackDoor,
    /// AMD's security processor loaded it and set them (amdgpu's way on
    /// APUs); the driver leaves them alone.
    Psp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The display engine has no DMCUB (CC_DC_PIPE_DIS says so).
    Absent,
    /// It didn't say it was ready; SCRATCH0 as it was.
    Timeout { status: u32 },
}

/// DMCUB's registers: DCN's segment 2 base (in register words).
struct Regs<'c, C: Card> {
    card: &'c mut C,
    seg2: u32,
}

impl<C: Card> Regs<'_, C> {
    fn read(&mut self, r: u32) -> u32 {
        self.card.read(self.seg2 + r)
    }
    fn write(&mut self, r: u32, v: u32) {
        self.card.write(self.seg2 + r, v)
    }
    fn update(&mut self, r: u32, clear: u32, set: u32) {
        let v = self.read(r);
        self.write(r, (v & !clear) | set)
    }
    /// Wait up to `us` microseconds for `done`.
    fn wait(&mut self, us: u32, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        for _ in 0..us.div_ceil(10) {
            if done(self) {
                return true;
            }
            self.card.delay_us(10);
        }
        done(self)
    }
    /// Code window `n` onto `offset` (an address on the GPU's side),
    /// seen by DMCUB from `base`, `size` bytes, its top `top_less` short
    /// of the end (the code and stack windows end on their last byte, the
    /// others one past it, as DC sets them).
    fn window(&mut self, n: u32, offset: u64, base: u32, size: u64, top_less: u32) {
        self.write(reg::CW_OFFSET + 2 * n, offset as u32);
        self.write(reg::CW_OFFSET + 2 * n + 1, (offset >> 32) as u32);
        self.write(reg::CW_BASE + n, base);
        let top = base.wrapping_add(size as u32).wrapping_sub(top_less);
        self.write(reg::CW_TOP + n, (top & TOP_ADDRESS) | WINDOW_ENABLE);
    }
}

/// Whether the code window is the one the back door would set for
/// `layout` at `place` (the security processor may keep its own).
pub fn back_door_took(card: &mut impl Card, seg2: u32, layout: &Layout, place: Place) -> bool {
    let w = &layout.windows[INST];
    let top = (CW0_BASE.wrapping_add(w.size as u32).wrapping_sub(1) & TOP_ADDRESS) | WINDOW_ENABLE;
    let at = place.system + w.at;
    card.read(seg2 + reg::CW_TOP) == top
        && card.read(seg2 + reg::CW_OFFSET) == at as u32
        && card.read(seg2 + reg::CW_OFFSET + 1) == (at >> 32) as u32
}

/// Whether the display engine has a DMCUB.
pub fn present(card: &mut impl Card, seg2: u32) -> bool {
    card.read(seg2 + reg::CC_DC_PIPE_DIS) & DC_DMCUB_ENABLE != 0
}

/// Stop whatever DMCUB runs and hold it in reset, the rings emptied.
pub fn stop(card: &mut impl Card, seg2: u32) {
    let mut r = Regs { card, seg2 };
    if r.read(reg::CNTL2) & CNTL2_SOFT_RESET == 0 {
        let cmd = GPINT_STATUS | (GPINT_STOP_FW << 16);
        r.write(reg::GPINT_DATAIN1, cmd);
        // Each wait gives up after 100 ms (a hung firmware is reset all
        // the same).
        r.wait(100_000, |r| r.read(reg::GPINT_DATAIN1) == cmd & !GPINT_STATUS);
        r.wait(100_000, |r| r.read(reg::SCRATCH7) == STOP_FW_RESPONSE);
        r.wait(100_000, |r| r.read(reg::CNTL) & CNTL_PWAIT_MODE_STATUS != 0);
    }
    if r.read(reg::CNTL) & CNTL_ENABLE != 0 {
        r.update(reg::CNTL2, 0, CNTL2_SOFT_RESET);
        r.update(reg::MMHUBBUB_SOFT_RESET, 0, DMUIF_SOFT_RESET);
        r.update(reg::CNTL, CNTL_ENABLE, 0);
    }
    for p in [
        reg::INBOX1_RPTR,
        reg::INBOX1_WPTR,
        reg::OUTBOX1_RPTR,
        reg::OUTBOX1_WPTR,
        reg::OUTBOX0_RPTR,
        reg::OUTBOX0_WPTR,
        reg::SCRATCH0,
        reg::GPINT_DATAIN1,
    ] {
        r.write(p, 0);
    }
}

/// Start the firmware whose windows `layout` places at `place` (already
/// filled: the code (for the back door), the data and the VBIOS copied
/// in, the mailbox, the trace buffer and the state cleared), with
/// `options` in SCRATCH14; DMCUB's boot status once it says it is ready.
pub fn start(
    card: &mut impl Card,
    seg2: u32,
    layout: &Layout,
    place: Place,
    load: Load,
    options: u32,
) -> Result<u32, Error> {
    if !present(card, seg2) {
        return Err(Error::Absent);
    }
    stop(card, seg2);
    let mut r = Regs { card, seg2 };
    let w = &layout.windows;
    let gpu = |i: usize| place.gpu + w[i].at;
    let system = |i: usize| place.system + w[i].at;

    // The back door: the code and stack windows, while DMCUB's security
    // reset is held.
    if load == Load::BackDoor {
        r.update(reg::SEC_CNTL, 0, SEC_RESET);
        r.window(0, system(INST), CW0_BASE, w[INST].size, 1);
        r.window(1, system(STACK), CW1_BASE, w[STACK].size, 1);
        r.update(reg::SEC_CNTL, SEC_RESET | SEC_MEM_UNIT_ID, 0x20 << 8);
    }

    r.window(3, gpu(VBIOS), CW3_BASE, w[VBIOS].size, 0);
    r.window(4, gpu(MAILBOX), CW4_BASE, w[MAILBOX].size, 0);
    r.window(5, gpu(TRACE), CW5_BASE, w[TRACE].size, 0);
    r.write(reg::REGION5_OFFSET, gpu(TRACE) as u32);
    r.write(reg::REGION5_OFFSET_HIGH, (gpu(TRACE) >> 32) as u32);
    r.write(reg::REGION5_TOP_ADDRESS, ((w[TRACE].size as u32 - 1) & TOP_ADDRESS) | WINDOW_ENABLE);
    r.window(6, gpu(STATE), CW6_BASE, w[STATE].size, 0);

    r.write(reg::OUTBOX0_BASE_ADDRESS, REGION5_BASE + TRACE_ENTRY_OFFSET);
    r.write(reg::OUTBOX0_SIZE, w[TRACE].size as u32 - TRACE_ENTRY_OFFSET);
    r.write(reg::INBOX1_BASE_ADDRESS, CW4_BASE);
    r.write(reg::INBOX1_SIZE, RB_SIZE);
    r.write(reg::OUTBOX1_BASE_ADDRESS, CW4_BASE + RB_SIZE);
    r.write(reg::OUTBOX1_SIZE, RB_SIZE);
    r.write(reg::SCRATCH14, options);

    // Out of reset (no PSP version to tell it: Raphael has no DMCU).
    r.update(reg::MMHUBBUB_SOFT_RESET, DMUIF_SOFT_RESET, 0);
    r.write(reg::SCRATCH15, 0);
    r.update(reg::CNTL, 0, CNTL_ENABLE | CNTL_TRACEPORT_EN);
    r.update(reg::CNTL2, CNTL2_SOFT_RESET, 0);

    let ready = STATUS_DAL_FW | STATUS_MAILBOX_READY;
    let mut status = 0;
    if r.wait(100_000, |r| {
        status = r.read(reg::SCRATCH0);
        status & ready == ready
    }) {
        Ok(status)
    } else {
        Err(Error::Timeout { status })
    }
}

/// DMCUB's VBIOS commands (dmub_cmd.h, `DMUB_CMD__VBIOS` 128 and its sub
/// types; command_table2.c builds them where the VBIOS has no tables, as
/// on Raphael: `encoder_control_digx_v1_5`, `transmitter_control_v1_7`,
/// `set_pixel_clock_v7`). A command is 64 bytes: the header (type, sub
/// type, flags, the payload's size in bits 29:24, `dmub_cmd_header`) and
/// its payload (atomfirmware.h's `dig_encoder_stream_setup_parameters_v1_5`,
/// `set_pixel_clock_parameter_v1_7`; dmub_cmd.h's
/// `dmub_dig_transmitter_control_data_v1_7`).
pub mod vbios {
    pub const TYPE: u8 = 128;
    pub const ENCODER_CONTROL: u8 = 0;
    pub const TRANSMITTER_CONTROL: u8 = 1;
    pub const SET_PIXEL_CLOCK: u8 = 2;
    pub const DISP_POWER_GATING: u8 = 3;
    /// atomfirmware.h and atombios.h: encoder and transmitter modes,
    /// actions, the PHY's PLLs, the CRTCs, colour depth.
    pub const MODE_HDMI: u8 = 3;
    pub const STREAM_SETUP: u8 = 0x0F;
    pub const TRANSMITTER_DISABLE: u8 = 0;
    pub const TRANSMITTER_ENABLE: u8 = 1;
    pub const TRANSMITTER_INIT: u8 = 7;
    pub const COMBOPHY_PLL0: u8 = 20;
    pub const CRTC1: u8 = 0;
    pub const BPC_8: u8 = 2;
    /// atomfirmware.h: `ATOM_INIT`, `ATOM_DISABLE`; set pixel clock's
    /// `PIXEL_CLOCK_V7_MISC_FORCE_PROG_PPLL`; no CRTC, no encoder mode.
    pub const INIT: u8 = 7;
    pub const DISABLE: u8 = 0;
    pub const FORCE_PROG_PPLL: u8 = 1;
    pub const NO_CRTC: u8 = 0xFF;
    pub const MODE_NONE: u8 = 0x0F;
    pub const MODE_DVI: u8 = 2;
}

/// DMCUB's idle commands (dmub_cmd.h, `DMUB_CMD__IDLE_OPT` 72): the
/// driver's power state (sub type 3: D0 is 1) and "save the init state"
/// (sub type 1, `DMUB_CMD__IDLE_OPT_DCN_SAVE_INIT`), which DC sends after
/// its hardware init (core/dc.c, `dc_hardware_init`; amdgpu_dm.c).
pub mod idle {
    pub const TYPE: u8 = 72;
    pub const SAVE_INIT: u8 = 1;
    pub const SET_DC_POWER_STATE: u8 = 3;
    pub const D0: u8 = 1;
}

/// A VBIOS command with `payload` after its header.
pub fn command(sub: u8, payload: &[u8]) -> [u8; 64] {
    typed(vbios::TYPE, sub, payload, payload.len())
}

/// A command of type `kind`, its header saying `size` payload bytes
/// (some commands' structures are bigger than what they carry).
pub fn typed(kind: u8, sub: u8, payload: &[u8], size: usize) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0] = kind;
    c[1] = sub;
    c[3] = (size as u8) & 0x3F;
    c[4..4 + payload.len()].copy_from_slice(payload);
    c
}

/// Display power gating (VBIOS sub type 3, atomfirmware.h's
/// `enable_disp_power_gating_parameters_v2_1`): pipe `pipe` (CRTC1 is 0),
/// `action` (INIT, ENABLE or DISABLE). DC's hardware init sends INIT for
/// the first pipe, then DISABLE for every pipe (as amdgpu's ring on
/// the reference PC shows).
pub fn power_gating(pipe: u8, action: u8) -> [u8; 64] {
    command(vbios::DISP_POWER_GATING, &[pipe, action, 0, 0])
}

/// DIG transmitter control (v1.7): PHY `phy` (0 is UNIPHY A), `action`,
/// the encoder mode, lanes, the symbol clock (10 kHz units), the HPD pin
/// (1 is HPD1), the connector's object ID.
pub fn transmitter(phy: u8, action: u8, mode: u8, lanes: u8, symclk_10khz: u32, hpd: u8, connector: u8) -> [u8; 64] {
    let mut p = [0u8; 16];
    p[..4].copy_from_slice(&[phy, action, mode, lanes]);
    p[4..8].copy_from_slice(&symclk_10khz.to_le_bytes());
    // The DIG front end is chosen by the driver (`dig_encoder_sel_to_atom`
    // gives 0); no HPO.
    p[8..11].copy_from_slice(&[hpd, 0, connector]);
    // The command's structure is a union whose size DC puts in the header
    // (60 bytes, as amdgpu's ring on the reference PC shows).
    typed(vbios::TYPE, vbios::TRANSMITTER_CONTROL, &p, 60)
}

/// Set pixel clock (v7): `pixclk_100hz` on PLL `pll` for CRTC `crtc`, the
/// encoder's object ID, its mode, `misc` (`FORCE_PROG_PPLL`), the deep
/// colour ratio (0 for 8 bits).
pub fn pixel_clock(pixclk_100hz: u32, pll: u8, encoder: u8, mode: u8, misc: u8, crtc: u8, deep_color: u8) -> [u8; 64] {
    let mut p = [0u8; 16];
    p[..4].copy_from_slice(&pixclk_100hz.to_le_bytes());
    p[4..10].copy_from_slice(&[pll, encoder, mode, misc, crtc, deep_color]);
    command(vbios::SET_PIXEL_CLOCK, &p)
}

/// A PHY PLL powered down (DC's `cs_power_down` at init: no clock, no
/// CRTC, forced).
pub fn pll_off(pll: u8) -> [u8; 64] {
    pixel_clock(0, pll, 0, vbios::MODE_NONE, vbios::FORCE_PROG_PPLL, vbios::NO_CRTC, 0)
}

/// DIG encoder stream setup (v1.5): DIG `dig`, its mode, lanes, the pixel
/// clock (10 kHz), bits per colour.
pub fn encoder_setup(dig: u8, mode: u8, lanes: u8, pclk_10khz: u32, bpc: u8) -> [u8; 64] {
    let mut p = [0u8; 12];
    p[..4].copy_from_slice(&[dig, vbios::STREAM_SETUP, mode, lanes]);
    p[4..8].copy_from_slice(&pclk_10khz.to_le_bytes());
    p[8] = bpc;
    command(vbios::ENCODER_CONTROL, &p)
}

/// Send `cmd` through INBOX1 (the mailbox window's first ring, at GPU
/// address `ring`) and wait up to 100 ms for DMCUB to take it (dmub_srv.c:
/// `dmub_rb_push_front` writes it at the write pointer, which moves on 64
/// bytes and wraps at the ring's size; `dmub_srv_cmd_execute` sets
/// INBOX1_WPTR; `dmub_srv_wait_for_idle` waits for INBOX1_RPTR to reach
/// it).
pub fn send(dev: &mut (impl Card + crate::psp::Memory), seg2: u32, ring: u64, cmd: &[u8; 64]) -> Result<(), Error> {
    let wptr = dev.read(seg2 + reg::INBOX1_WPTR) % RB_SIZE;
    dev.put(ring + u64::from(wptr), cmd);
    dev.flush();
    let next = (wptr + 64) % RB_SIZE;
    dev.write(seg2 + reg::INBOX1_WPTR, next);
    for _ in 0..10_000 {
        if dev.read(seg2 + reg::INBOX1_RPTR) == next {
            return Ok(());
        }
        dev.delay_us(10);
    }
    Err(Error::Timeout { status: dev.read(seg2 + reg::INBOX1_RPTR) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    const SEG2: u32 = 0x34C0;

    /// Registers in a map; DMCUB "boots" when it is enabled and out of
    /// reset.
    #[derive(Default)]
    struct Dcn {
        r: BTreeMap<u32, u32>,
        waited: u32,
        boots: bool,
    }

    impl Card for Dcn {
        fn read(&mut self, reg: u32) -> u32 {
            let v = self.r.get(&reg).copied().unwrap_or(0);
            let on = |d: &Self, r: u32| d.r.get(&(SEG2 + r)).copied().unwrap_or(0);
            if reg == SEG2 + reg::SCRATCH0
                && self.boots
                && on(self, reg::CNTL) & CNTL_ENABLE != 0
                && on(self, reg::CNTL2) & CNTL2_SOFT_RESET == 0
            {
                return 0x43;
            }
            v
        }
        fn write(&mut self, reg: u32, value: u32) {
            self.r.insert(reg, value);
        }
        fn delay_us(&mut self, us: u32) {
            self.waited += us;
        }
    }

    /// A firmware file like the reference PC's: its sizes and metadata, the
    /// metadata four bytes before the code's end.
    fn file(inst_const: usize, state: u32, trace: u32) -> Vec<u8> {
        let inst = PSP_HEADER + inst_const + PSP_FOOTER;
        let mut b = vec![0u8; 0x100 + inst];
        let len = b.len() as u32;
        b[0..4].copy_from_slice(&len.to_le_bytes());
        b[4..8].copy_from_slice(&40u32.to_le_bytes());
        b[0x10..0x14].copy_from_slice(&0x0500_3700u32.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&0x100u32.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&(inst as u32).to_le_bytes());
        let meta = 0x100 + PSP_HEADER + inst_const - 4 - META_SIZE;
        b[meta..meta + 4].copy_from_slice(&META_MAGIC.to_le_bytes());
        b[meta + 4..meta + 8].copy_from_slice(&state.to_le_bytes());
        b[meta + 8..meta + 12].copy_from_slice(&trace.to_le_bytes());
        b[meta + 12..meta + 16].copy_from_slice(&0x0500_3700u32.to_le_bytes());
        b[meta + 16] = 1;
        b
    }

    #[test]
    fn reads_the_file() {
        let b = file(0x3A520, 0xC880, 0x1_0010);
        let fw = Firmware::new(&b).unwrap();
        assert_eq!(fw.version, 0x0500_3700);
        assert_eq!(fw.inst_const.len(), 0x3A520);
        assert_eq!(fw.signed.len(), 0x3A720);
        assert!(fw.bss.is_empty());
        assert_eq!(fw.meta, Some(Meta { state_size: 0xC880, trace_size: 0x1_0010, version: 0x0500_3700, dal: true }));
        // Without metadata: the defaults, a 256-byte footer.
        let mut b = b;
        let at = b.windows(4).position(|w| w == META_MAGIC.to_le_bytes()).unwrap();
        b[at] = 0;
        let fw = Firmware::new(&b).unwrap();
        assert_eq!((fw.meta, fw.inst_const.len()), (None, 0x3A520));
        assert!(Firmware::new(&b[..0x30]).is_none());
        assert!(Firmware::new(&b[..b.len() - 1]).is_none());
    }

    #[test]
    fn lays_out_the_windows() {
        let b = file(0x3A520, 0xC880, 0x1_0010);
        let l = Layout::new(&Firmware::new(&b).unwrap(), 0xAE00);
        let at: Vec<_> = l.windows.iter().map(|w| (w.at, w.size)).collect();
        assert_eq!(
            at,
            [
                (0, 0x3A540),
                (0x3A600, 0xA_0000),
                (0xD_A600, 0),
                (0xD_A600, 0xAE00),
                (0xE_5400, 0x4000),
                (0xE_9400, 0x1_0040),
                (0xF_9500, 0xC880),
                (0x10_5E00, 0x400),
            ]
        );
        assert_eq!(l.size, 0x10_7000);
    }

    /// With the reference PC's firmware sizes and VBIOS, placed where amdgpu placed
    /// its block (GPU F4_1F80_0000h), the windows from CW3 on, region 5
    /// and the rings are what amdgpu left on the reference PC (umr, 2026-10-28).
    #[test]
    fn starts_as_amdgpu_does() {
        let b = file(0x3A520, 0xC880, 0x1_0010);
        let l = Layout::new(&Firmware::new(&b).unwrap(), 0xAE00);
        let place = Place { gpu: 0xF4_1F80_0000, system: 0x20_5F80_0000 };
        let mut d = Dcn { boots: true, ..Default::default() };
        d.r.insert(SEG2 + reg::CC_DC_PIPE_DIS, 0x0001_0000);
        // A firmware running (amdgpu's), out of reset.
        d.r.insert(SEG2 + reg::CNTL, 0x0019_00C6);
        d.r.insert(SEG2 + reg::SEC_CNTL, 0x0000_2000);
        assert_eq!(start(&mut d, SEG2, &l, place, Load::BackDoor, OPTION_ENABLE_DPIA), Ok(0x43));
        let at = |r: u32| d.r.get(&(SEG2 + r)).copied().unwrap_or(0);
        let observed = [
            (reg::CW_OFFSET + 6, 0x1F8D_A600),
            (reg::CW_OFFSET + 7, 0xF4),
            (reg::CW_TOP + 3, 0x8300_AE00),
            (reg::CW_OFFSET + 8, 0x1F8E_5400),
            (reg::CW_TOP + 4, 0x8400_4000),
            (reg::CW_OFFSET + 10, 0x1F8E_9400),
            (reg::CW_TOP + 5, 0x8501_0040),
            (reg::REGION5_OFFSET, 0x1F8E_9400),
            (reg::REGION5_OFFSET_HIGH, 0xF4),
            (reg::REGION5_TOP_ADDRESS, 0x8001_003F),
            (reg::CW_OFFSET + 12, 0x1F8F_9500),
            (reg::CW_TOP + 6, 0x8600_C880),
            (reg::INBOX1_BASE_ADDRESS, 0x6400_0000),
            (reg::INBOX1_SIZE, 0x2000),
            (reg::OUTBOX1_BASE_ADDRESS, 0x6400_2000),
            (reg::OUTBOX1_SIZE, 0x2000),
            (reg::OUTBOX0_BASE_ADDRESS, 0xA000_0010),
            (reg::OUTBOX0_SIZE, 0x1_0030),
            (reg::SCRATCH14, 0x80),
            (reg::SEC_CNTL, 0x2000),
        ];
        for (r, v) in observed {
            assert_eq!(at(r), v, "register {r:#x}");
        }
        // The code and stack windows are system addresses.
        assert_eq!((at(reg::CW_OFFSET), at(reg::CW_OFFSET + 1)), (0x5F80_0000, 0x20));
        assert_eq!((at(reg::CW_OFFSET + 2), at(reg::CW_OFFSET + 3)), (0x5F83_A600, 0x20));
        // Their tops are the windows' last bytes (amdgpu's PSP, loading
        // the code itself, ends CW0 on the code's exact size, 3A51Fh).
        assert_eq!(at(reg::CW_TOP), 0x8003_A53F);
        assert_eq!(at(reg::CW_TOP + 1), 0x8109_FFFF);
        // On, out of reset; the running firmware was told to stop and,
        // not answering here, waited for (100 ms for the acknowledgement,
        // 100 for the response; amdgpu's CNTL already says it waits).
        assert_eq!(at(reg::CNTL) & (CNTL_ENABLE | CNTL_TRACEPORT_EN), CNTL_ENABLE | CNTL_TRACEPORT_EN);
        assert_eq!(at(reg::CNTL2) & CNTL2_SOFT_RESET, 0);
        assert!((200_000..210_000).contains(&d.waited));
        assert!(back_door_took(&mut d, SEG2, &l, place));
        // Loaded by the PSP: its code and stack windows stay as they were.
        let mut d = Dcn { boots: true, ..Default::default() };
        d.r.insert(SEG2 + reg::CC_DC_PIPE_DIS, DC_DMCUB_ENABLE);
        d.r.insert(SEG2 + reg::CW_TOP, 0x8003_A51F);
        assert_eq!(start(&mut d, SEG2, &l, place, Load::Psp, 0), Ok(0x43));
        assert_eq!(d.r.get(&(SEG2 + reg::CW_TOP)), Some(&0x8003_A51F));
        assert_eq!(d.r.get(&(SEG2 + reg::CW_OFFSET)), None);
        assert!(!back_door_took(&mut d, SEG2, &l, place));
    }

    #[test]
    fn says_when_it_doesnt_start() {
        let b = file(0x3A520, 0xC880, 0x1_0010);
        let l = Layout::new(&Firmware::new(&b).unwrap(), 0xAE00);
        let place = Place { gpu: 0xF4_0000_0000, system: 0x20_4000_0000 };
        let mut d = Dcn::default();
        assert_eq!(start(&mut d, SEG2, &l, place, Load::BackDoor, 0), Err(Error::Absent));
        d.r.insert(SEG2 + reg::CC_DC_PIPE_DIS, DC_DMCUB_ENABLE);
        // Held in reset already: no stop command, no wait for it.
        d.r.insert(SEG2 + reg::CNTL2, CNTL2_SOFT_RESET);
        assert_eq!(start(&mut d, SEG2, &l, place, Load::BackDoor, 0), Err(Error::Timeout { status: 0 }));
        assert!((100_000..110_000).contains(&d.waited));
    }

    #[test]
    fn refpc_firmware() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/gpu/refpc/dcn_3_1_5_dmcub.bin");
        let Ok(b) = std::fs::read(path) else { return };
        let fw = Firmware::new(&b).unwrap();
        assert_eq!(fw.version, 0x0500_3700);
        // amdgpu's code window on the reference PC ends at 3A51Fh.
        assert_eq!(fw.inst_const.len(), 0x3A520);
        let meta = fw.meta.unwrap();
        assert_eq!((meta.state_size, meta.trace_size, meta.dal), (0xC880, 0x1_0010, true));
    }

    /// The commands' bytes, as DC lays them out.
    #[test]
    fn vbios_commands() {
        // As amdgpu's ring on the reference PC holds them for 1080p60 on HDMI (its
        // transmitter commands also carry an HPO instance, F6h, that DIO
        // links don't use).
        let t = transmitter(0, vbios::TRANSMITTER_ENABLE, vbios::MODE_HDMI, 4, 14_850, 1, 0);
        assert_eq!(&t[..20], &[128, 1, 0, 60, 0, 1, 3, 4, 0x02, 0x3A, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert!(t[20..].iter().all(|&b| b == 0));
        let p = pixel_clock(1_485_000, vbios::COMBOPHY_PLL0, 0x1E, vbios::MODE_HDMI, 0, vbios::CRTC1, 0);
        assert_eq!(&p[..20], &[128, 2, 0, 16, 0xC8, 0xA8, 0x16, 0, 20, 0x1E, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&pll_off(21)[..14], &[128, 2, 0, 16, 0, 0, 0, 0, 21, 0, 0x0F, 1, 0xFF, 0]);
        let e = encoder_setup(0, vbios::MODE_HDMI, 4, 14_850, vbios::BPC_8);
        assert_eq!(&e[..16], &[128, 0, 0, 12, 0, 0x0F, 3, 4, 0x02, 0x3A, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&power_gating(0, vbios::INIT)[..8], &[128, 3, 0, 4, 0, 7, 0, 0]);
    }

    /// Commands go into INBOX1 and DMCUB's read pointer follows.
    #[test]
    fn sends_through_the_inbox() {
        #[derive(Default)]
        struct Dev {
            r: BTreeMap<u32, u32>,
            mem: BTreeMap<u64, u8>,
            flushed: bool,
            dead: bool,
        }
        impl Card for Dev {
            fn read(&mut self, reg: u32) -> u32 {
                self.r.get(&reg).copied().unwrap_or(0)
            }
            fn write(&mut self, reg: u32, v: u32) {
                self.r.insert(reg, v);
                // DMCUB takes what it is given, once it was flushed.
                if reg == SEG2 + reg::INBOX1_WPTR && self.flushed && !self.dead {
                    self.r.insert(SEG2 + reg::INBOX1_RPTR, v);
                }
            }
            fn delay_us(&mut self, _: u32) {}
        }
        impl crate::psp::Memory for Dev {
            fn put(&mut self, gpu: u64, data: &[u8]) {
                for (i, b) in data.iter().enumerate() {
                    self.mem.insert(gpu + i as u64, *b);
                }
                self.flushed = false;
            }
            fn get32(&mut self, _: u64) -> u32 {
                0
            }
            fn flush(&mut self) {
                self.flushed = true;
            }
        }
        let mut d = Dev::default();
        let ring = 0xF4_0100_0000 + 0xE_5400;
        let cmd = transmitter(0, vbios::TRANSMITTER_INIT, vbios::MODE_HDMI, 4, 0, 1, 0x0C);
        for i in 0..130u64 {
            send(&mut d, SEG2, ring, &cmd).unwrap();
            assert_eq!(d.mem.get(&(ring + (i * 64) % 0x2000)), Some(&128));
        }
        assert_eq!(d.r.get(&(SEG2 + reg::INBOX1_WPTR)), Some(&((130 * 64) % 0x2000)));
        // A DMCUB that doesn't answer.
        let mut dead = Dev { dead: true, ..Default::default() };
        assert_eq!(send(&mut dead, SEG2, ring, &cmd), Err(Error::Timeout { status: 0 }));
    }
}
