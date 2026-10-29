// SPDX-License-Identifier: MIT OR Apache-2.0

//! AMD display (ADR 0171, M32 phase 4): finding the card (step 3), its
//! memory (step 5), the display's microcontroller, DMCUB (step 6), and
//! HDMI monitors' EDID over DDC (step 7). For AMD's RDNA 2 integrated GPUs (Raphael, the reference PC's;
//! Rembrandt, the development machine's) the driver maps the registers, reads the IP discovery
//! table (where the display engine's registers are, and its version) and
//! the VBIOS from the ACPI VFCT table (the display paths: connectors, PHYs,
//! HPD pins), turns the HPD blocks on and says what is connected. Then the
//! GPU's view of its memory: an APU's "VRAM" is a carve-out of system
//! memory that the platform firmware places in the GPU's address space
//! (the memory hub's FB location) and at a system address (its FB offset);
//! the display engine is given the same view, and BAR 0 shows the
//! carve-out to the CPU. With AMD's DMCUB firmware in /lib/firmware
//! (full graphics, ADR 0171's addenda), the driver has AMD's security
//! processor load it (`slate_amdgpu::psp`) and starts DMCUB
//! (`slate_amdgpu::dmub`). Then it lights the first connected HDMI
//! monitor at its preferred mode (`slate_amdgpu::mode`) and offers it as
//! a DRM card with flips and a hardware cursor (step 8). On the command
//! line, `slate.amd=off` leaves the display to the firmware, and for
//! bring-up `slate.amd.bars` stops at the colour squares and
//! `slate.amd.fb` shows a test image first.
//!
//! Sources (docs/gpu/amd.md, Linux v7.2.12 read as documentation, ADR
//! 0157's addendum):
//! - amdgpu_discovery.c: `mmMM_INDEX` 0h, `mmMM_DATA` 1h, `mmMM_INDEX_HI`
//!   6h and `mmRCC_CONFIG_MEMSIZE` DE3h (register words, before the IP
//!   bases are known); amdgpu_device.c (`amdgpu_device_mm_access`): the
//!   address's low 31 bits with bit 31 set in MM_INDEX, the rest in
//!   MM_INDEX_HI, then MM_DATA.
//! - dcn_3_1_5_offset.h: `regHPD0_DC_HPD_INT_STATUS` 1F14h and
//!   `regHPD0_DC_HPD_CONTROL` 1F16h in segment 2, eight words per HPD
//!   block; dcn_3_1_5_sh_mask.h: `DC_HPD_SENSE` bit 1, `DC_HPD_EN` bit
//!   28, the connection timer bits 12:0, the RX interrupt timer 25:16.
//! - The values amdgpu leaves in DC_HPD_CONTROL on the reference PC: 10FA09C4h
//!   (on, timers 2500 and 250), observed with umr.
//! - mmhub_2_3_0_offset.h (MMHUB 2.4.1's registers, as umr's database
//!   places them on the reference PC): `mmMMMC_VM_FB_OFFSET` 8D7h,
//!   `mmMMMC_VM_FB_LOCATION_BASE` 8ECh and `_TOP` 8EDh in segment 1;
//!   dcn_3_1_5_offset.h: `regDCN_VM_FB_LOCATION_BASE` 475h, `_TOP` 476h,
//!   `regDCN_VM_FB_OFFSET` 477h in segment 2; their sh_mask files: 24-bit
//!   fields in 16 MiB units. DC gives the display engine the memory hub's
//!   values (dcn31_hubbub.c, `hubbub31_init_dchub_sys_ctx`, from
//!   amdgpu_dm.c's `mmhub_read_system_context`: the GMC's FB start, end
//!   and VRAM base offset). On the reference PC: FB
//!   F400h to F41Fh (GPU addresses F4_0000_0000h up, 512 MiB), offset
//!   2040h (system address 20_4000_0000h).
//! - amdgpu_device.c: BAR 0 shows the GPU's memory from its start
//!   (`aper_base`); the driver checks it against MM_INDEX/MM_DATA.
//! - The PSP (`slate_amdgpu::psp`) loads DMCUB when its trusted OS runs,
//!   as amdgpu does on APUs (amdgpu_psp.c, `psp_hw_start`: the ring, the
//!   TOC, the TMR; then `LOAD_IP_FW`). amdgpu's TMR was 10 MiB at the
//!   carve-out's offset 480 MiB on the reference PC, a multiple of its size ("naturally
//!   aligned", `psp_tmr_init`), below the GART table and IP discovery at
//!   the top; Slate's goes in the same place for the size the TOC asks.
//!   The TOC's name: psp_v13_0.c (`psp_init_toc_microcode`, "%s_toc.bin"
//!   for "psp_13_0_5").
//! - Writes through BAR 0 reach the GPU's memory after an HDP flush
//!   (amdgpu_device.c, `amdgpu_device_flush_hdp`, which an APU needs only
//!   when the carve-out is reached through the BAR, as in a guest):
//!   nbio_v7_2.c, `regBIF_BX_PF0_HDP_MEM_COHERENCY_FLUSH_CNTL` (NBIF 7.3.0's
//!   segment 2, F7h in nbio_7_2_0_offset.h) written with 0, then a read of
//!   the memory size register to post it (hdp_v5_2.c).
//! - The DMCUB firmware's name for DCN 3.1.5: amdgpu_dm.c
//!   (`FIRMWARE_DCN_315_DMUB`, "amdgpu/dcn_3_1_5_dmcub.bin"); after
//!   copying the code in, DC reads it back so that it has reached memory
//!   before DMCUB runs (dmub_srv.c, `dmub_flush_buffer_mem`).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_amdgpu::atom::{Connector, Rom, transmitter};
use slate_amdgpu::discovery::{self, Table};
use slate_amdgpu::dmub;
use slate_amdgpu::i2c::Ddc;
use slate_amdgpu::interp;
use slate_amdgpu::mode;
use slate_amdgpu::psp::{self, Psp};
use slate_amdgpu::scanout;

use super::dma::{Mmio, delay_ms};
use super::pci::{Bar, Device};
use crate::sync::IrqSpinLock;
use crate::{kprintln, log_info, log_warn};

/// PCI IDs: Raphael (Ryzen 7000's Radeon), Rembrandt (Radeon 680M and
/// 660M); AMD's display class.
const IDS: [u16; 2] = [0x164E, 0x1681];

pub fn matches(d: &Device) -> bool {
    d.vendor == 0x1002 && d.class == 0x03 && IDS.contains(&d.device)
}

// Byte offsets of register words 0h, 1h, 6h and DE3h.
const MM_INDEX: usize = 0;
const MM_DATA: usize = 4;
const MM_INDEX_HI: usize = 0x6 * 4;
const RCC_CONFIG_MEMSIZE: usize = 0xDE3 * 4;

const HPD_INT_STATUS: u64 = 0x1F14;
const HPD_CONTROL: u64 = 0x1F16;
const HPD_SEGMENT: usize = 2;
const HPD_STRIDE: u64 = 8;
const HPD_SENSE: u32 = 1 << 1;
const HPD_ON: u32 = (1 << 28) | (250 << 16) | 2500;

const MMHUB_FB_OFFSET: u64 = 0x8D7;
const MMHUB_FB_BASE: u64 = 0x8EC;
const MMHUB_FB_TOP: u64 = 0x8ED;
const MMHUB_SEGMENT: usize = 1;
const DCN_FB_BASE: u64 = 0x475;
const DCN_FB_TOP: u64 = 0x476;
const DCN_FB_OFFSET: u64 = 0x477;
const FB_FIELD: u32 = 0xFF_FFFF;
/// Where in the carve-out the driver checks BAR 0 (a word it puts back).
const PROBE_AT: u64 = 32 << 20;
/// Where DMCUB's windows go (about a megabyte), in the part BAR 0 shows.
const DMCUB_AT: u64 = 16 << 20;
/// Where the PSP's ring, command buffer and fence go (a page each), and
/// the 1 MiB buffer for the images it is given.
const PSP_AT: u64 = 24 << 20;
const PSP_IMAGE_AT: u64 = 25 << 20;
const PSP_TOC: &str = "amdgpu/psp_13_0_5_toc.bin";
/// amdgpu_psp.h: `PSP_TMR_SIZE` without a TOC, `PSP_TMR_ALIGNMENT`.
const TMR_SIZE: u32 = 0x40_0000;
const TMR_ALIGN: u64 = 1 << 20;
/// The carve-out's top 16 MiB stay clear (the GART table, IP discovery).
const TOP_KEPT: u64 = 16 << 20;
const HDP_FLUSH: u64 = 0xF7;
const NBIF_HDP_SEGMENT: usize = 2;

/// Where the blocks DMCUB's start needs are (register words).
#[derive(Clone, Copy)]
struct Bases {
    /// GC's segments 0 (SDMA0, the GFX hub, the CP) and 1 (the RLC), 0
    /// if there is no GC.
    gc0: u32,
    gc1: u32,
    nbio0: u32,
    dcn1: u32,
    dcn3: u32,
    dcn2: u32,
    mp0: u32,
    hdp_flush: usize,
}

impl Bases {
    fn mode(&self) -> mode::Bases {
        mode::Bases { dcn1: self.dcn1, dcn2: self.dcn2, dcn3: self.dcn3, mp0: self.mp0, nbio0: self.nbio0 }
    }
}

/// A link (`slate_amdgpu::mode::Link`) and, for a connected HDMI monitor,
/// its preferred mode.
#[derive(Clone, Copy, Debug)]
struct Link {
    link: mode::Link,
    mode: Option<slate_amdgpu::otg::Timing>,
}

/// The card's registers and memory for slate_amdgpu's PSP and DMCUB.
struct Gpu<'a> {
    regs: &'a Mmio,
    vram: &'a Vram,
    hdp_flush: usize,
}

impl interp::Card for Gpu<'_> {
    fn read(&mut self, reg: u32) -> u32 {
        self.regs.read32(reg as usize * 4)
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.regs.write32(reg as usize * 4, value)
    }
    fn delay_us(&mut self, us: u32) {
        Card(self.regs).delay_us(us)
    }
}

impl psp::Memory for Gpu<'_> {
    fn put(&mut self, gpu: u64, data: &[u8]) {
        if !self.vram.write(gpu.wrapping_sub(self.vram.gpu), data) {
            log_warn!("amd: {gpu:#x} is outside what BAR 0 shows");
        }
    }
    fn get32(&mut self, gpu: u64) -> u32 {
        self.vram.read32(gpu.wrapping_sub(self.vram.gpu))
    }
    fn flush(&mut self) {
        self.regs.write32(self.hdp_flush, 0);
        self.regs.read32(RCC_CONFIG_MEMSIZE);
    }
}

/// The PSP loads DMCUB's signed image: a ring, the TOC, the TMR, then
/// the image; where it put the code.
/// The PSP's ring, command and fence buffers and the image's, in the
/// carve-out that starts at GPU address `base`.
fn psp_buffers(base: u64) -> psp::Buffers {
    psp::Buffers {
        ring: base + PSP_AT,
        command: base + PSP_AT + 0x1000,
        fence: base + PSP_AT + 0x2000,
        image: base + PSP_IMAGE_AT,
        image_size: 1 << 20,
    }
}

fn psp_load(a: super::pci::Address, gpu: &mut Gpu, bases: Bases, fw: &dmub::Firmware) -> Result<u64, psp::Error> {
    let mp0 = bases.mp0;
    let base = gpu.vram.gpu;
    let mut p = Psp::new(mp0, psp_buffers(base));
    log_info!(
        "amd {a:?}: PSP: trusted OS {:#x}, mailbox {:#x}",
        interp::Card::read(gpu, mp0 + psp::reg::C2PMSG_81),
        interp::Card::read(gpu, mp0 + psp::reg::C2PMSG_64)
    );
    if let Err(e) = p.create_ring(gpu) {
        // A ring left by an earlier driver: take it away and try again.
        log_info!("amd {a:?}: PSP: no ring ({e:?}); destroying the old ones");
        p.destroy_rings(gpu);
        p.create_ring(gpu)?;
    }
    let toc = super::firmware::read(PSP_TOC);
    let size = match toc.as_deref().and_then(psp::toc) {
        Some(t) => p.load_toc(gpu, t)?,
        None => TMR_SIZE,
    };
    // 0 after a TMR an earlier driver left (the reference PC, once): the usual size.
    let size = if size == 0 { TMR_SIZE } else { size };
    let size = u64::from(size).div_ceil(TMR_ALIGN) * TMR_ALIGN;
    let at = (gpu.vram.size - TOP_KEPT - size) / size * size;
    match p.setup_tmr(gpu, base + at, gpu.vram.system + at, size as u32) {
        Ok(()) => log_info!("amd {a:?}: PSP: TMR of {} KiB at {:#x}", size >> 10, base + at),
        // One left by an earlier driver may still serve.
        Err(e) => log_warn!("amd {a:?}: PSP: no new TMR ({e:?})"),
    }
    // GC's and SDMA's firmware first, in amdgpu's order (M32 phase 6,
    // ADR 0172): with `slate.amd.gcfw`, for now.
    if bases.gc0 != 0 && crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.gcfw") {
        gc_firmware(a, gpu, &mut p, bases);
    }
    p.load_ip_fw(gpu, psp::FW_DMUB, fw.signed)
}

/// GC 10.3.6's and SDMA 5.2.6's images through the PSP
/// (`slate_amdgpu::gcfw`), then AUTOLOAD_RLC, and the RLC's autoload
/// waited for (CP_STAT 0 and BOOTLOAD_COMPLETE, up to a second). Whether
/// it completed.
fn gc_firmware(a: super::pci::Address, gpu: &mut Gpu, p: &mut Psp, bases: Bases) -> bool {
    use slate_amdgpu::gcfw;
    let names = [gcfw::SDMA, gcfw::CE, gcfw::PFP, gcfw::ME, gcfw::MEC, gcfw::MEC2, gcfw::RLC];
    let files: Vec<Option<Vec<u8>>> = names.iter().map(|n| super::firmware::read(n)).collect();
    let [Some(sdma), Some(ce), Some(pfp), Some(me), Some(mec), Some(mec2), Some(rlc)] = &files[..] else {
        log_info!("amd {a:?}: GC's firmware isn't all there; the graphics engines stay as they are");
        return false;
    };
    let f = gcfw::Files { sdma, ce, pfp, me, mec, mec2, rlc };
    let images = match gcfw::images(&f) {
        Ok(i) => i,
        Err(e) => {
            log_warn!("amd {a:?}: GC's firmware: {e:?}");
            return false;
        }
    };
    // GC reset first, whatever an earlier driver left (a running RLC
    // makes the PSP refuse its autoload; a MEC an earlier one ran doesn't
    // come back without it).
    if interp::Card::read(gpu, bases.gc1 + gcfw::RLC_CNTL) & 1 != 0 {
        log_info!("amd {a:?}: GC's RLC was left running");
    }
    gcfw::soft_reset(gpu, bases.gc0, bases.gc1);
    let before = interp::Card::read(gpu, bases.gc1 + gcfw::RLC_RLCS_BOOTLOAD_STATUS);
    for (kind, image) in &images {
        if let Err(e) = p.load_ip_fw(gpu, *kind, image) {
            log_warn!("amd {a:?}: PSP didn't load GC's firmware of type {kind} ({} bytes): {e:?}", image.len());
            return false;
        }
    }
    if let Err(e) = p.submit(gpu, gcfw::AUTOLOAD_RLC, &[]) {
        log_warn!("amd {a:?}: PSP didn't start the RLC's autoload: {e:?}");
        return false;
    }
    let start = crate::time::monotonic_ns();
    let (mut stat, mut boot) = (0, 0);
    while crate::time::monotonic_ns() - start < 1_000_000_000 {
        stat = interp::Card::read(gpu, bases.gc0 + gcfw::CP_STAT);
        boot = interp::Card::read(gpu, bases.gc1 + gcfw::RLC_RLCS_BOOTLOAD_STATUS);
        if stat == 0 && boot & gcfw::BOOTLOAD_COMPLETE != 0 {
            break;
        }
        delay_ms(1);
    }
    let done = stat == 0 && boot & gcfw::BOOTLOAD_COMPLETE != 0;
    GC_LOADED.store(true, core::sync::atomic::Ordering::Relaxed);
    log_info!(
        "amd {a:?}: PSP loaded GC's {} images; the RLC's autoload {} after {} ms (bootload status {before:#x} then \
         {boot:#x}, CP_STAT {stat:#x}, RLC_CNTL {:#x})",
        images.len(),
        if done { "completed" } else { "didn't complete" },
        (crate::time::monotonic_ns() - start) / 1_000_000,
        interp::Card::read(gpu, bases.gc1 + 0x4C00)
    );
    done
}

/// What the driver started, to stop before the system goes down: DMCUB
/// (its ring), and the output it lit, if any.
struct Lit {
    regs: Mmio,
    vram: Vram,
    bases: Bases,
    ring: u64,
    link: Option<Link>,
}

impl Vram {
    fn copy(&self) -> Vram {
        Vram {
            gpu: self.gpu,
            size: self.size,
            system: self.system,
            bar: self.bar,
            bar_size: self.bar_size,
            bar_phys: self.bar_phys,
        }
    }
}

static LIT: IrqSpinLock<Option<Lit>> = IrqSpinLock::new(None);

/// GC's firmware was loaded (and its RLC started) by this driver.
static GC_LOADED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Switch a lit output off as the system goes down, as amdgpu does when it
/// lets the card go (amdgpu_dm.c, `dm_hw_fini`: the display powered down,
/// DMCUB stopped; amdgpu_psp.c, `psp_hw_fini`: the rings destroyed). A
/// DMCUB started later (the next boot without a reset, a guest after a
/// guest) can't switch off a link that an earlier one left on: its
/// transmitter commands never finish (ADR 0171). With nothing lit,
/// DMCUB is stopped all the same (a later one finds it "restore
/// required" otherwise and takes no commands), and SDMA0 halted
/// (`sdma_v5_2_hw_fini`).
pub fn shutdown() {
    let Some(lit) = LIT.lock().take() else { return };
    let mut gpu = Gpu { regs: &lit.regs, vram: &lit.vram, hdp_flush: lit.bases.hdp_flush };
    if lit.bases.gc0 != 0 {
        slate_amdgpu::sdma::stop(&mut gpu, lit.bases.gc0);
    }
    let r = match &lit.link {
        Some(l) => mode::switch_off(&mut gpu, lit.bases.mode(), lit.ring, l.link),
        None => {
            dmub::stop(&mut gpu, lit.bases.dcn2);
            Ok(())
        }
    };
    if lit.bases.gc0 != 0 && GC_LOADED.load(core::sync::atomic::Ordering::Relaxed) {
        // The compute queue off while the MEC still runs, then the engines.
        let off = slate_amdgpu::cp::stop(&mut gpu, lit.bases.gc0);
        slate_amdgpu::gcfw::stop(&mut gpu, lit.bases.gc0, lit.bases.gc1);
        log_info!("amd: GC's engines stopped for shutdown (the compute queue dequeued: {off})");
    }
    // The TMR stays (amdgpu's `psp_hw_fini` destroys it, but the PSP
    // refused DESTROY_TMR here with 8000_0306h, and the next LOAD_TOC then
    // asked for no TMR); the next driver sets up its own over it.
    let b = psp::Buffers { ring: 0, command: 0, fence: 0, image: 0, image_size: 0 };
    let rings = Psp::new(lit.bases.mp0, b).destroy_rings(&mut gpu);
    use core::sync::atomic::Ordering::Relaxed;
    log_info!(
        "amd: display off for shutdown ({r:?}), DMCUB stopped, PSP rings {rings:x?}; {} flips, {} before the last took; {} overlay changes, {} underflows; {} copies on SDMA0, {} failed; {} 2D requests, {} submissions failed",
        FLIPS.load(Relaxed),
        LATE.load(Relaxed),
        OVERLAYS.load(Relaxed),
        UNDERFLOWS.load(Relaxed),
        COPIES.load(Relaxed),
        COPY_FAILS.load(Relaxed),
        TWOD.load(Relaxed),
        TWOD_FAILS.load(Relaxed)
    );
}

/// The card's registers (by register word) for slate_amdgpu.
struct Card<'a>(&'a Mmio);

impl interp::Card for Card<'_> {
    fn read(&mut self, reg: u32) -> u32 {
        self.0.read32(reg as usize * 4)
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.0.write32(reg as usize * 4, value)
    }
    fn delay_us(&mut self, us: u32) {
        let end = crate::time::monotonic_ns() + u64::from(us) * 1000;
        while crate::time::monotonic_ns() < end {
            core::hint::spin_loop();
        }
    }
}

/// The GPU's memory, as the GPU, the system and the CPU see it.
pub struct Vram {
    /// Its first GPU address.
    pub gpu: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Its system address (the carve-out).
    pub system: u64,
    /// BAR 0: how much of it the CPU sees, from its start.
    pub bar: *mut u8,
    pub bar_size: u64,
    /// BAR 0's physical address.
    pub bar_phys: u64,
}

// SAFETY: BAR 0 stays mapped for the kernel's life, and every access to it
// is a single volatile word (as `Mmio`'s).
unsafe impl Send for Vram {}

impl Vram {
    /// Write `data` at `at` (an offset in the GPU's memory) through BAR 0.
    pub fn write(&self, at: u64, data: &[u8]) -> bool {
        if at.saturating_add(data.len() as u64) > self.bar_size {
            return false;
        }
        for (i, chunk) in data.chunks(4).enumerate() {
            let mut w = [0u8; 4];
            w[..chunk.len()].copy_from_slice(chunk);
            // SAFETY: Inside BAR 0, which stays mapped (checked above); a
            // device memory window, so volatile, a word at a time.
            unsafe { self.bar.add(at as usize + 4 * i).cast::<u32>().write_volatile(u32::from_le_bytes(w)) }
        }
        true
    }

    /// Fill `len` bytes at `at` with zeros.
    pub fn clear(&self, at: u64, len: u64) -> bool {
        if at.saturating_add(len) > self.bar_size {
            return false;
        }
        for i in (0..len).step_by(4) {
            // SAFETY: As in `write`.
            unsafe { self.bar.add((at + i) as usize).cast::<u32>().write_volatile(0) }
        }
        true
    }

    pub fn read32(&self, at: u64) -> u32 {
        if at + 4 > self.bar_size {
            return u32::MAX;
        }
        // SAFETY: As in `write`.
        unsafe { self.bar.add(at as usize).cast::<u32>().read_volatile() }
    }

    /// Whether `data` is at `at` (read back through BAR 0).
    pub fn holds(&self, at: u64, data: &[u8]) -> bool {
        if at.saturating_add(data.len() as u64) > self.bar_size {
            return false;
        }
        data.chunks(4).enumerate().all(|(i, chunk)| {
            // SAFETY: As in `write`.
            let w = unsafe { self.bar.add(at as usize + 4 * i).cast::<u32>().read_volatile() }.to_le_bytes();
            w[..chunk.len()] == *chunk
        })
    }
}

/// What a monitor's EDID says; its preferred mode.
fn report_edid(
    a: super::pci::Address,
    name: &str,
    edid: Result<Vec<u8>, slate_amdgpu::i2c::Error>,
) -> Option<(slate_amdgpu::otg::Timing, Monitor)> {
    let bytes = match edid {
        Ok(b) => b,
        Err(e) => {
            log_warn!("amd {a:?}: {name}: no EDID over DDC ({e:?})");
            return None;
        }
    };
    let Some(info) = slate_edid::modes::read(&bytes) else {
        log_warn!("amd {a:?}: {name}: a bad EDID ({} bytes)", bytes.len());
        return None;
    };
    let b = &info.base;
    let v = core::str::from_utf8(&b.vendor).unwrap_or("?");
    let model = core::str::from_utf8(&b.name[..b.name_len]).unwrap_or("?").trim();
    log_info!(
        "amd {a:?}: {name}: EDID {} bytes, {v} {:04x} {model:?}, {} modes",
        bytes.len(),
        b.product,
        info.modes().len()
    );
    if let Some(m) = info.preferred() {
        let t = &m.timing;
        log_info!(
            "amd {a:?}: {name}: preferred {}x{} at {} kHz, {}x{} in all, HDMI TMDS up to {:?} kHz",
            t.hactive,
            t.vactive,
            t.clock_khz,
            t.htotal,
            t.vtotal,
            info.hdmi_max_tmds_khz
        );
    }
    let monitor = Monitor { edid: bytes.clone(), size_mm: b.size_mm };
    info.preferred().map(|m| {
        let t = m.timing;
        let timing = slate_amdgpu::otg::Timing {
            clock_khz: t.clock_khz,
            hactive: t.hactive,
            hsync_start: t.hsync_start,
            hsync_end: t.hsync_end,
            htotal: t.htotal,
            vactive: t.vactive,
            vsync_start: t.vsync_start,
            vsync_end: t.vsync_end,
            vtotal: t.vtotal,
            hsync_positive: t.hsync_positive,
            vsync_positive: t.vsync_positive,
        };
        (timing, monitor)
    })
}

/// The card's links, their monitors (in the same order) and its sysfs
/// path.
struct Outputs {
    links: Vec<Link>,
    monitors: Vec<Option<Monitor>>,
    sys: alloc::string::String,
}

/// A connected monitor's EDID and size, for its card.
#[derive(Clone, Debug)]
struct Monitor {
    edid: Vec<u8>,
    size_mm: (u32, u32),
}

/// The DMCUB firmware for a display engine.
fn dmcub_file(version: (u8, u8, u8)) -> Option<&'static str> {
    match version {
        (3, 1, 5) => Some("amdgpu/dcn_3_1_5_dmcub.bin"),
        _ => None,
    }
}

/// Copy DMCUB's firmware (and the VBIOS it reads) into the carve-out and
/// start it (step 6).
fn start_dmcub(
    a: super::pci::Address,
    regs: &Mmio,
    vram: &Vram,
    bases: Bases,
    vbios: &[u8],
    outputs: &Outputs,
    bin: Option<Vec<u8>>,
) {
    let seg2 = bases.dcn2;
    let Some(bin) = bin else {
        log_info!("amd {a:?}: no DMCUB firmware: the display is the firmware's (full graphics needs it)");
        return;
    };
    let Some(fw) = dmub::Firmware::new(&bin) else {
        log_warn!("amd {a:?}: the DMCUB firmware file isn't one");
        return;
    };
    let layout = dmub::Layout::new(&fw, vbios.len());
    let w = &layout.windows;
    let at = |i: usize| DMCUB_AT + w[i].at;
    let copied = vram.write(at(dmub::INST), fw.inst_const)
        && vram.write(at(dmub::BSS), fw.bss)
        && vram.write(at(dmub::VBIOS), vbios)
        && [dmub::MAILBOX, dmub::TRACE, dmub::STATE, dmub::SCRATCH].iter().all(|&i| vram.clear(at(i), w[i].size));
    if !copied || !vram.holds(at(dmub::INST), fw.inst_const) {
        log_warn!("amd {a:?}: DMCUB's firmware didn't go into the GPU's memory");
        return;
    }
    let place = dmub::Place { gpu: vram.gpu + DMCUB_AT, system: vram.system + DMCUB_AT };
    let mut card = Card(regs);
    let reg = |card: &mut Card, r: u32| interp::Card::read(card, seg2 + r);
    // The PSP loads it where its trusted OS runs (amdgpu's way on APUs);
    // else the back door.
    let mut gpu = Gpu { regs, vram, hdp_flush: bases.hdp_flush };
    let load = if interp::Card::read(&mut gpu, bases.mp0 + psp::reg::C2PMSG_81) != 0 {
        // DMCUB stopped first: the PSP replaces code it may be running.
        dmub::stop(&mut gpu, seg2);
        match psp_load(a, &mut gpu, bases, &fw) {
            Ok(at) => {
                log_info!("amd {a:?}: PSP loaded DMCUB's firmware at {at:#x}");
                if GC_LOADED.load(core::sync::atomic::Ordering::Relaxed) {
                    compute_test(a, &mut gpu, bases);
                }
                dmub::Load::Psp
            }
            Err(e) => {
                log_warn!("amd {a:?}: the PSP didn't load DMCUB's firmware ({e:?}); trying the back door");
                dmub::Load::BackDoor
            }
        }
    } else {
        dmub::Load::BackDoor
    };
    let started = dmub::start(&mut card, seg2, &layout, place, load, dmub::OPTION_ENABLE_DPIA);
    if load == dmub::Load::BackDoor && !dmub::back_door_took(&mut card, seg2, &layout, place) {
        log_warn!(
            "amd {a:?}: the security processor keeps DMCUB's code window (CW0 top {:#x})",
            reg(&mut card, dmub::reg::CW_TOP)
        );
    }
    match started {
        Ok(status) => {
            log_info!(
                "amd {a:?}: DMCUB running firmware {:#010x} (status {status:#x}, {} KiB at {:#x})",
                reg(&mut card, dmub::reg::SCRATCH1),
                layout.size >> 10,
                place.gpu
            );
            // DC's hardware init through DMCUB, as amdgpu's ring on the reference PC
            // shows it: display power gating INIT for the first pipe and
            // off for the four (dcn10_hwseq.c, `dcn10_init_hw`'s
            // `enable_display_power_gating`), the driver in D0, the init
            // state saved (core/dc.c, `dc_hardware_init`).
            let ring = place.gpu + w[dmub::MAILBOX].at;
            let taken = mode::init(&mut gpu, bases.mode(), ring);
            log_info!("amd {a:?}: DMCUB took {taken} of 7 init commands");
            *LIT.lock() = Some(Lit { regs: Mmio(gpu.regs.0), vram: gpu.vram.copy(), bases, ring, link: None });
            // The first connected HDMI monitor lit (the display pattern
            // generator's colour squares first), then a framebuffer on it
            // and the card; `slate.amd.bars` stops at the squares,
            // `slate.amd=off` lights nothing.
            let has = |word: &str| crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == word);
            if !has("slate.amd=off")
                && let Some(i) = outputs.links.iter().position(|l| l.mode.is_some())
            {
                let l = &outputs.links[i];
                let lit = light(a, &mut gpu, bases, ring, DMCUB_AT + w[dmub::TRACE].at, l);
                if lit
                    && !has("slate.amd.bars")
                    && let Some(t) = l.mode
                {
                    let monitor = outputs.monitors.get(i).cloned().flatten();
                    framebuffer(a, &mut gpu, bases, &t, monitor, &outputs.sys, has("slate.amd.fb"));
                }
            } else if !has("slate.amd=off") {
                log_info!("amd {a:?}: no HDMI monitor connected; nothing lit");
            }
        }
        Err(e) => {
            log_warn!(
                "amd {a:?}: DMCUB didn't start firmware {:#010x}: {e:?} (CNTL {:#x}, SEC_CNTL {:#x}, SCRATCH1 {:#x})",
                fw.version,
                reg(&mut card, dmub::reg::CNTL),
                reg(&mut card, dmub::reg::SEC_CNTL),
                reg(&mut card, dmub::reg::SCRATCH1)
            );
            dmcub_report(a, &mut card, seg2, vram, DMCUB_AT + w[dmub::TRACE].at);
        }
    }
}

/// CTA-861's 1920x1080 at 60 Hz (VIC 16: 148.5 MHz, 2200 x 1125, both
/// syncs positive), the timing the reference PC's monitor prefers.
const VIC16: slate_amdgpu::otg::Timing = slate_amdgpu::otg::Timing {
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

/// Where the scanout buffers go in the carve-out (in what BAR 0 shows):
/// the first (the bring-up test image), the second (step 8's flips;
/// room for 4K's 32 MiB) and the cursor's image.
const FB_AT: u64 = 64 << 20;
const FB2_AT: u64 = 96 << 20;
const CURSOR_AT: u64 = 128 << 20;
/// The overlay plane's two buffers (each room for the screen, 4K's 32 MiB).
const OVERLAY_AT: [u64; 2] = [136 << 20, 168 << 20];

/// Pipe 0's flips and cursor (`slate_amdgpu::scanout`) for the card over
/// its scanout buffers (`drm::bootfb::Hardware`).
struct Hardware {
    regs: Mmio,
    bases: mode::Bases,
    aperture: mode::Aperture,
    seg2: u32,
    seg3: u32,
    hdp_flush: usize,
    timing: slate_amdgpu::otg::Timing,
    /// Each buffer's GPU address, and where they are mapped.
    gpu: [u64; 2],
    first: u64,
    second: u64,
    /// The address last flipped to.
    asked: core::sync::atomic::AtomicU64,
    /// The cursor's image: its GPU address and where it is mapped
    /// (write-combining, `scanout::CURSOR_PITCH` square), and what it
    /// shows now.
    cursor_gpu: u64,
    cursor_map: u64,
    cursor: IrqSpinLock<Option<scanout::Cursor>>,
    /// The overlay's buffers (pipe 1): their GPU addresses, where they are
    /// mapped, and what it shows (none if they don't fit).
    overlay_gpu: [u64; 2],
    overlay_map: Option<[u64; 2]>,
    overlay: IrqSpinLock<Option<(mode::Place, mode::Surface)>>,
    /// SDMA0, for the copies into the buffers above (none: the CPU
    /// copies).
    engine: Option<crate::sched::wait::Mutex<Engine>>,
}

/// The overlay's pipe.
const OVERLAY_PIPE: u32 = 1;

/// Flips asked for, those asked before the last one took, and whether the
/// cursor's registers were reported (said at shutdown, and once, to check
/// on the reference PC without looking at its monitor).
static FLIPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static LATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CURSOR_SAID: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Overlay changes (shown, moved, flipped, taken off), and underflows
/// seen in pipes 0 and 1 (HUBP_UNDERFLOW_STATUS) when the overlay
/// changed, said at shutdown.
static OVERLAYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static UNDERFLOWS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Copies done on SDMA0 and those left to the CPU after it failed, and
/// whether the first was checked (said at shutdown, and once).
static COPIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static COPY_FAILS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// 2D requests done, and submissions that failed (said at shutdown).
static TWOD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TWOD_FAILS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// With `slate.amd.copy=check`, the first copy of whole rows and the
/// first of part of them, each checked pixel by pixel (bring-up: slow).
static COPY_SAID: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];

impl Hardware {
    fn card(&self) -> Card<'_> {
        Card(&self.regs)
    }

    fn reg(&self, r: u32) -> u32 {
        interp::Card::read(&mut self.card(), r)
    }

    /// What was written through the BAR, for the hub to see: the
    /// write-combining buffers drained, HDP's cache flushed.
    fn flush(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.regs.write32(self.hdp_flush, 0);
        self.regs.read32(RCC_CONFIG_MEMSIZE);
    }

    /// The pipes the cursor goes on: pipe 0's screen, and the overlay's.
    fn pipes(&self) -> ([mode::Place; 2], usize) {
        let screen = scanout::screen(&self.timing);
        match *self.overlay.lock() {
            Some((p, _)) => ([screen, p], 2),
            None => ([screen; 2], 1),
        }
    }

    /// Pipes 0's and 1's underflow status, counted and cleared
    /// (HUBP_UNDERFLOW_STATUS, bits 28 to 30 of DCHUBP_CNTL; writing
    /// HUBP_UNDERFLOW_CLEAR, bit 31, clears them).
    fn underflows(&self) -> u32 {
        let mut seen = 0;
        for pipe in [0, OVERLAY_PIPE] {
            let r = self.seg2 + mode::on_pipe(mode::reg::HUBP0_DCHUBP_CNTL, pipe);
            let v = self.reg(r);
            if v & (7 << 28) != 0 {
                seen += 1;
                interp::Card::write(&mut self.card(), r, v | (1 << 31));
                interp::Card::write(&mut self.card(), r, v & !(1 << 31));
            }
        }
        UNDERFLOWS.fetch_add(u64::from(seen), core::sync::atomic::Ordering::Relaxed);
        seen
    }
}

impl super::drm::bootfb::Hardware for Hardware {
    fn second(&self) -> Option<u64> {
        Some(self.second)
    }
    fn flip(&self, i: usize) {
        use core::sync::atomic::Ordering::Relaxed;
        let to = self.gpu[i];
        if !self.flipped() {
            LATE.fetch_add(1, Relaxed);
        }
        let n = FLIPS.fetch_add(1, Relaxed);
        self.asked.store(to, core::sync::atomic::Ordering::Release);
        self.flush();
        scanout::flip(&mut self.card(), self.seg2, 0, to);
        if n == 1 {
            // The second flip: the first buffer again, once the first flip
            // took.
            let end = crate::time::monotonic_ns() + 50_000_000;
            while !self.flipped() && crate::time::monotonic_ns() < end {}
            log_info!(
                "amd: flipped to {to:#x}: {} (in use {:#x}, flip control {:#x})",
                self.flipped(),
                u64::from(self.reg(self.seg2 + scanout::reg::EARLIEST_INUSE_HIGH)) << 32
                    | u64::from(self.reg(self.seg2 + scanout::reg::EARLIEST_INUSE)),
                self.reg(self.seg2 + scanout::reg::FLIP_CONTROL)
            );
        }
    }
    fn flipped(&self) -> bool {
        scanout::flipped(&mut self.card(), self.seg2, 0, self.asked.load(core::sync::atomic::Ordering::Acquire))
    }
    fn cursor(&self, image: Option<&super::drm::CursorImage>, at: (i32, i32)) -> bool {
        let pitch = scanout::CURSOR_PITCH;
        let c = match image {
            Some(i) if i.width <= pitch && i.height <= pitch => {
                // The image into the cursor's surface, rows `pitch` apart.
                let dst = self.cursor_map as *mut u32;
                for y in 0..pitch {
                    for x in 0..pitch {
                        let px = if x < i.width && y < i.height { i.pixels[(y * i.width + x) as usize] } else { 0 };
                        // SAFETY: (x, y) is inside the cursor's surface,
                        // which stays mapped.
                        unsafe { dst.add((y * pitch + x) as usize).write_volatile(px) };
                    }
                }
                self.flush();
                Some(scanout::Cursor { address: self.cursor_gpu, width: i.width, height: i.height })
            }
            Some(_) => None,
            None => None,
        };
        let (pipes, n) = self.pipes();
        let mut shown = self.cursor.lock();
        scanout::cursor(&mut self.card(), self.seg2, self.seg3, &self.timing, c.as_ref(), at, &pipes[..n]);
        *shown = c;
        if c.is_some() && !CURSOR_SAID.swap(true, core::sync::atomic::Ordering::Relaxed) {
            let r = |w: u32| self.reg(self.seg2 + w);
            log_info!(
                "amd: cursor at {at:?}: control {:#x}, DPP {:#x}, size {:#x}, position {:#x}, address {:#x}{:08x}",
                r(scanout::reg::CURSOR_CONTROL),
                r(scanout::reg::CUR0_CONTROL),
                r(scanout::reg::CURSOR_SIZE),
                r(scanout::reg::CURSOR_POSITION),
                r(scanout::reg::CURSOR_SURFACE_ADDRESS_HIGH),
                r(scanout::reg::CURSOR_SURFACE_ADDRESS)
            );
        }
        image.is_none() || c.is_some()
    }
    fn move_cursor(&self, at: (i32, i32)) {
        let (pipes, n) = self.pipes();
        if let Some(c) = *self.cursor.lock() {
            scanout::move_cursor(&mut self.card(), self.seg2, self.seg3, &self.timing, &c, at, &pipes[..n]);
        }
    }
    fn overlay_buffers(&self) -> Option<[u64; 2]> {
        self.overlay_map
    }
    fn show_overlay(&self, at: Option<super::drm::bootfb::OverlayAt>) {
        use core::sync::atomic::Ordering::Relaxed;
        let n = OVERLAYS.fetch_add(1, Relaxed);
        let b = self.bases;
        let mut shown = self.overlay.lock();
        let Some(a) = at else {
            if shown.take().is_some() {
                mode::overlay_off(&mut self.card(), b, OVERLAY_PIPE);
            }
            return;
        };
        let p = mode::Place { pipe: OVERLAY_PIPE, at: a.at, size: a.size };
        let s = mode::Surface { address: self.overlay_gpu[a.buffer], pitch: self.timing.hactive, alpha: a.alpha };
        self.flush();
        match *shown {
            None => match mode::overlay(&mut self.card(), b, &self.timing, s, self.aperture, p) {
                Ok(o) => {
                    *shown = Some((p, s));
                    // What pipe 1 and the MPC show, the first time (to
                    // check on the reference PC without looking at its monitor).
                    if n == 0 {
                        let r = |w: u32| self.reg(self.seg2 + mode::on_pipe(w, OVERLAY_PIPE));
                        let r3 = |w: u32| self.reg(self.seg3 + w);
                        log_info!(
                            "amd: overlay on pipe {OVERLAY_PIPE} at {:?}, {:?}: {o:x?}; recout {:#x} {:#x}, MPC tree {:#x} (MPCC1 top {:#x} bottom {:#x} control {:#x}), DET1 {:#x}, compressed buffer {:#x}",
                            a.at,
                            a.size,
                            r(mode::reg::DSCL0_RECOUT_START),
                            r(mode::reg::DSCL0_RECOUT_SIZE),
                            r3(mode::reg::MPC_OUT0_MUX),
                            r3(mode::reg::MPCC_STRIDE + mode::reg::MPCC0_TOP_SEL),
                            r3(mode::reg::MPCC_STRIDE + mode::reg::MPCC0_BOT_SEL),
                            r3(mode::reg::MPCC_STRIDE + mode::reg::MPCC0_CONTROL),
                            self.reg(self.seg2 + mode::reg::DET1_CTRL),
                            self.reg(self.seg2 + mode::reg::COMPBUF_CTRL)
                        );
                    }
                }
                Err(e) => log_warn!("amd: no overlay on pipe {OVERLAY_PIPE}: {e:?}"),
            },
            // Only the buffer changed: a flip, as pipe 0's.
            Some((q, t)) if q == p && (t.pitch, t.alpha) == (s.pitch, s.alpha) => {
                scanout::flip(&mut self.card(), self.seg2, OVERLAY_PIPE, s.address);
                *shown = Some((p, s));
            }
            Some(_) => {
                mode::move_overlay(&mut self.card(), b, &self.timing, s, self.aperture, p);
                *shown = Some((p, s));
            }
        }
        drop(shown);
        if self.underflows() != 0 {
            log_warn!("amd: a pipe underflowed (overlay change {n})");
        }
    }
    fn overlay_flipped(&self) -> bool {
        match *self.overlay.lock() {
            Some((_, s)) => scanout::flipped(&mut self.card(), self.seg2, OVERLAY_PIPE, s.address),
            None => true,
        }
    }
    fn copy(
        &self,
        fb: &Arc<super::drm::Framebuffer>,
        from: (u32, u32),
        to: super::drm::bootfb::Target,
        at: (u32, u32),
        size: (u32, u32),
    ) -> bool {
        use super::drm::bootfb::Target;
        let Some(engine) = &self.engine else { return false };
        let dst = match to {
            Target::Screen(i) => self.gpu[i],
            Target::Overlay(i) => self.overlay_gpu[i],
        };
        let dst = slate_amdgpu::sdma::Image { address: dst, pitch: self.timing.hactive, height: self.timing.vactive };
        let mut e = engine.lock();
        let kind = usize::from(size.0 * 4 != fb.pitch);
        let check = crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.copy=check")
            && !COPY_SAID[kind].load(core::sync::atomic::Ordering::Relaxed);
        let mapped = match to {
            Target::Screen(0) => self.first,
            Target::Screen(_) => self.second,
            Target::Overlay(i) => self.overlay_map.map_or(0, |m| m[i]),
        };
        if check {
            // The rectangle marked first: what the copy didn't write stays
            // DEADBEEFh.
            for y in at.1..at.1 + size.1 {
                for x in at.0..at.0 + size.0 {
                    // SAFETY: inside the buffer, mapped for the card's life.
                    unsafe {
                        ((mapped + u64::from(y * self.timing.hactive + x) * 4) as *mut u32).write_volatile(0xDEAD_BEEF)
                    };
                }
            }
            self.flush();
        }
        let t = crate::time::monotonic_ns();
        let done = e.copy(&self.regs, fb, from, dst, at, size);
        let us = (crate::time::monotonic_ns() - t) / 1000;
        if done && check && !COPY_SAID[kind].swap(true, core::sync::atomic::Ordering::Relaxed) {
            // Checked against its framebuffer, to see on the reference PC without a
            // monitor.
            let pixel = |base: u64, x: u32, y: u32| {
                // SAFETY: (x, y) is inside the buffer (the screen's size),
                // mapped write-combining for the card's life.
                unsafe { ((base + u64::from(y * self.timing.hactive + x) * 4) as *const u32).read_volatile() }
            };
            let (w, h) = size;
            // Every pixel against its framebuffer's.
            let mut row = alloc::vec![0u8; (w * 4) as usize];
            let (mut first_bad, mut last_bad, mut bad) = (None, None, 0u64);
            for y in 0..h {
                fb.buffer.read(
                    u64::from(fb.offset) + u64::from(from.1 + y) * u64::from(fb.pitch) + u64::from(from.0) * 4,
                    &mut row,
                );
                for x in 0..w {
                    let s = u32::from_le_bytes(row[(x * 4) as usize..(x * 4 + 4) as usize].try_into().unwrap());
                    let d = pixel(mapped, at.0 + x, at.1 + y);
                    if d != s {
                        bad += 1;
                        first_bad.get_or_insert((x, y, d, s));
                        last_bad = Some((x, y, d, s));
                    }
                }
            }
            log_info!(
                "amd: the first copy of {} on SDMA0 ({w}x{h} to {to:?} at {at:?}, {us} us): {bad} pixels differ, the \
                 first at {first_bad:x?}, the last at {last_bad:x?}; fault {:x?}",
                if kind == 0 { "whole rows" } else { "part of them" },
                slate_amdgpu::gfxhub::fault(&mut self.card(), e.seg0)
            );
        }
        done
    }
    fn forget(&self, id: u32) {
        if let Some(engine) = &self.engine {
            engine.lock().forget(&self.regs, id);
        }
    }
    fn twod(&self) -> Option<&dyn super::drm::twod::TwoD> {
        self.engine.as_ref().map(|_| self as &dyn super::drm::twod::TwoD)
    }
    fn vblank(&self) -> Option<(u64, u64)> {
        let position = scanout::position(&mut self.card(), self.seg2);
        let now = crate::time::monotonic_ns();
        Some((now.saturating_sub(scanout::since_vblank_ns(&self.timing, position)), scanout::frame_ns(&self.timing)))
    }
}

/// The vblank clock checked against OTG0: two readings `ms` apart should
/// differ by whole frames; how far off (in microseconds) they are.
fn vblank_drift_us(hw: &Hardware, ms: u64) -> Option<i64> {
    use super::drm::bootfb::Hardware as _;
    let (first, period) = hw.vblank()?;
    delay_ms(ms);
    let (second, _) = hw.vblank()?;
    let off = (second - first) % period;
    let off = if off > period / 2 { off as i64 - period as i64 } else { off as i64 };
    Some(off / 1000)
}

/// A test image: a dark gradient, a grid every 120 pixels, a white border
/// and a diagonal, so that a wrong pitch, size or offset shows. Opaque:
/// the plane blends by its pixels' alpha (`ALPHA_EN`), and alpha 0 shows
/// only the black behind it.
fn test_pixel(x: u32, y: u32, w: u32, h: u32) -> u32 {
    let rgb = if x < 8 || y < 8 || x + 8 >= w || y + 8 >= h || x * h / w == y {
        0x00FF_FFFF
    } else if x % 120 == 0 || y % 120 == 0 {
        0x00C8_7A3C
    } else {
        let r = 0x20 + 0x60 * x / w;
        let b = 0x30 + 0x60 * y / h;
        (r << 16) | (0x28 << 8) | b
    };
    0xFF00_0000 | rgb
}

/// A framebuffer in the carve-out on OTG0's lit monitor through pipe 0
/// (`slate_amdgpu::mode::show`), black or a test image (`test`,
/// `slate.amd.fb`), then the card over it.
fn framebuffer(
    a: super::pci::Address,
    gpu: &mut Gpu,
    bases: Bases,
    t: &slate_amdgpu::otg::Timing,
    monitor: Option<Monitor>,
    sys: &str,
    test: bool,
) {
    use psp::Memory as _;
    let (w, h) = (t.hactive, t.vactive);
    if test {
        let mut row = alloc::vec![0u8; (w * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                row[(x * 4) as usize..(x * 4 + 4) as usize].copy_from_slice(&test_pixel(x, y, w, h).to_le_bytes());
            }
            gpu.vram.write(FB_AT + u64::from(y * w * 4), &row);
        }
    } else {
        gpu.vram.clear(FB_AT, u64::from(w * h * 4));
    }
    gpu.flush();
    let fb = gpu.vram.gpu + FB_AT;
    let surface = mode::Surface { address: fb, pitch: w, alpha: false };
    let aperture = mode::Aperture { base: gpu.vram.gpu, size: gpu.vram.size };
    let shown = mode::show(gpu, bases.mode(), t, surface, aperture);
    dump_plane(gpu.regs, u64::from(bases.dcn1), u64::from(bases.dcn2), u64::from(bases.dcn3));
    log_info!("amd {a:?}: framebuffer at {fb:#x}: {shown:x?}");
    if !matches!(shown, Ok(mode::Shown { flipped: true, .. })) {
        return;
    }
    // The scanout buffers as a card (`drm::bootfb`'s, which copies what it
    // shows, here into the buffer not shown, then flips to it): mapped
    // write-combining through BAR 0, XRGB8888, the monitor's mode, EDID
    // and size, an HDMI connector, the hardware cursor.
    let len = u64::from(w * h * 4);
    let map = |at: u64, len: u64| crate::mm::vmap::map_wc(crate::mm::PhysAddr(gpu.vram.bar_phys + at), len) as u64;
    let addr = map(FB_AT, len);
    let fits = FB2_AT + len <= CURSOR_AT && CURSOR_AT + (64 * 64 * 4) <= gpu.vram.bar_size;
    let overlay_fits = CURSOR_AT + (64 * 64 * 4) <= OVERLAY_AT[0]
        && OVERLAY_AT[0] + len <= OVERLAY_AT[1]
        && OVERLAY_AT[1] + len <= gpu.vram.bar_size;
    let hw = fits.then(|| Hardware {
        regs: Mmio(gpu.regs.0),
        bases: bases.mode(),
        aperture,
        seg2: bases.dcn2,
        seg3: bases.dcn3,
        hdp_flush: bases.hdp_flush,
        timing: *t,
        gpu: [fb, gpu.vram.gpu + FB2_AT],
        first: addr,
        second: map(FB2_AT, len),
        asked: core::sync::atomic::AtomicU64::new(fb),
        cursor_gpu: gpu.vram.gpu + CURSOR_AT,
        cursor_map: map(CURSOR_AT, 64 * 64 * 4),
        cursor: IrqSpinLock::new(None),
        overlay_gpu: OVERLAY_AT.map(|at| gpu.vram.gpu + at),
        overlay_map: overlay_fits.then(|| OVERLAY_AT.map(|at| map(at, len))),
        overlay: IrqSpinLock::new(None),
        engine: Engine::start(gpu, bases).map(crate::sched::wait::Mutex::new),
    });
    // The vblank clock (from OTG0's position) against itself 100 ms
    // later: whole frames apart if the position reads as the timing says.
    if let Some(h) = &hw {
        log_info!("amd {a:?}: vblank clock off by {:?} us over 100 ms", vblank_drift_us(h, 100));
    }
    let hw = hw.map(|h| -> Box<dyn super::drm::bootfb::Hardware> { Box::new(h) });
    let buffer = crate::arch::boot::Framebuffer {
        addr,
        width: w as usize,
        height: h as usize,
        pitch: (w * 4) as usize,
        bpp: 32,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };
    let refresh = (u64::from(t.clock_khz) * 1000 / (u64::from(t.htotal) * u64::from(t.vtotal))) as u32;
    let card = super::drm::bootfb::Scanout {
        driver: "slate-amd",
        description: "AMD display (DCN 3.1.5)",
        connector: super::drm::CONNECTOR_HDMIA,
        refresh,
        size_mm: monitor.as_ref().map_or((0, 0), |m| m.size_mm),
        edid: monitor.map(|m| m.edid),
    };
    let flips = match &hw {
        Some(h) if h.overlay_buffers().is_some() => "flips, hardware cursor, overlay",
        Some(_) => "flips, hardware cursor",
        None => "copies",
    };
    let minor = super::drm::bootfb::register_scanout(buffer, card, hw, sys, "pci");
    log_info!("amd {a:?}: card{minor}: {w}x{h} at {refresh} Hz on HDMI-A-1 ({flips})");
}

/// Light `l` with the pattern generator's colour squares
/// (`slate_amdgpu::mode::light`) and remember it, to switch it off at
/// shutdown; DMCUB's state if it doesn't light. Whether it lit.
fn light(a: super::pci::Address, gpu: &mut Gpu, bases: Bases, ring: u64, trace: u64, l: &Link) -> bool {
    let Some(t) = l.mode else { return false };
    let b = bases.mode();
    let smu = mode::smu_message(gpu, b, mode::smu::GET_PMFW_VERSION, 0);
    match mode::light(gpu, b, ring, l.link, &t) {
        Ok(lit) => {
            log_info!("amd {a:?}: colour squares at {}x{} (SMU {smu:x?}): {lit:x?}", t.hactive, t.vactive);
            if let Some(lit) = LIT.lock().as_mut() {
                lit.link = Some(*l);
            }
            true
        }
        Err(e) => {
            log_warn!("amd {a:?}: the link didn't light: {e:?}");
            let vram = gpu.vram;
            dmcub_report(a, gpu, bases.dcn2, vram, trace);
            false
        }
    }
}

/// What DMCUB shows (as DC's `dmub_dcn31_get_diagnostic_data` reads it:
/// its windows, fault addresses, scratch registers) and its trace buffer's
/// first entries (dmub_cmd.h, `dmcub_trace_buf_entry`: code, tick, two
/// parameters), while SCRATCH0 is watched for two more seconds.
fn dmcub_report(a: super::pci::Address, card: &mut impl interp::Card, seg2: u32, vram: &Vram, trace: u64) {
    let mut reg = |r: u32| interp::Card::read(card, seg2 + r);
    let mut status = 0;
    for _ in 0..200 {
        status = reg(dmub::reg::SCRATCH0);
        if status != 0 {
            break;
        }
        delay_ms(10);
    }
    log_info!("amd {a:?}: DMCUB SCRATCH0 later: {status:#x}");
    for (name, from, to) in [("windows", 0x1A5, 0x1C4), ("faults", 0x1CC, 0x1CF), ("scratch", 0x1E2, 0x1F2)] {
        let v: Vec<u32> = (from..=to).map(&mut reg).collect();
        log_info!("amd {a:?}: DMCUB {name} {from:#x}: {v:x?}");
    }
    log_info!(
        "amd {a:?}: DMCUB undefined-address fault {:#x}, timer {:#x}, CNTL2 {:#x}",
        reg(0x1FA),
        reg(dmub::reg::TIMER_CURRENT),
        reg(dmub::reg::CNTL2)
    );
    let words: Vec<u32> = (0..4 + 4 * 48).map(|i| vram.read32(trace + 4 * i)).collect();
    log_info!("amd {a:?}: DMCUB trace buffer: {words:x?}");
}

/// M32 phase 6's facts: with `slate.amd.gc`, the graphics block's state
/// as the driver finds it (read only; GC's registers may not answer while
/// it is power-gated, so not by default). Whether the RLC's autoload ran
/// (RLC_RLCS_BOOTLOAD_STATUS bit 31), the CP and SDMA0 halted or not, and
/// the GFX hub's view of memory (gc_10_3_0_offset.h; amdgpu's
/// gfx_v10_0.c, sdma_v5_2.c, gfxhub_v2_1.c, read as documentation).
fn gc_report(a: super::pci::Address, regs: &Mmio, table: &Table) {
    if !crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.gc") {
        return;
    }
    let (Some(gc), hdp) = (table.find(discovery::GC), table.find(discovery::HDP)) else {
        log_warn!("amd {a:?}: no GC in the IP discovery table");
        return;
    };
    let r = |seg: usize, w: u64| regs.read32((gc.base[seg] + w) as usize * 4);
    log_info!(
        "amd {a:?}: GC {:?} at {:#x?}, HDP {:?}: GRBM_STATUS {:#x}, STATUS2 {:#x}, CP_STAT {:#x}, ME_CNTL {:#x}, \
         MEC_CNTL {:#x}, RLC_CNTL {:#x}, RLC bootload {:#x}",
        gc.version,
        &gc.base[..gc.bases],
        hdp.map(|h| h.version),
        r(0, 0xDA4),
        r(0, 0xDA2),
        r(0, 0xF40),
        r(0, 0xF56),
        r(0, 0xF55),
        r(1, 0x4C00),
        r(1, 0x4E8D)
    );
    log_info!(
        "amd {a:?}: GC hub: FB {:#x}..{:#x} offset {:#x}, aperture low {:#x}, L1 TLB {:#x}, L2 {:#x}, \
         context 0 {:#x} table {:#x}; SDMA0: F32 {:#x}, status {:#x}, RB {:#x} base {:#x} rptr {:#x}",
        r(0, 0x16FC),
        r(0, 0x16FD),
        r(0, 0x16E7),
        r(0, 0x1701),
        r(0, 0x1703),
        r(0, 0x15BC),
        r(0, 0x15FC),
        r(0, 0x1667),
        r(0, 0x2A),
        r(0, 0x25),
        r(0, 0x80),
        r(0, 0x81),
        r(0, 0x83)
    );
    log_info!("amd {a:?}: GC hub: invalidation engine 17's range {:#x} {:#x}", r(0, 0x1665), r(0, 0x1666));
}

/// SDMA0 as the card's copy engine (M32 phase 6, step 4, ADR 0172): its
/// ring in the carve-out (at `SDMA_AT`, 64 KiB, its read pointer's
/// write-back and a fence after it), the GFX hub's GART with the
/// framebuffers it copies from mapped in (kept, with their buffers, until
/// the card forgets them), and the copies waited for.
struct Engine {
    seg0: u32,
    hdp_flush: usize,
    ring: slate_amdgpu::sdma::Ring,
    /// The ring and the fence page, and the GART's table, mapped
    /// write-combining.
    ring_map: u64,
    table_map: u64,
    /// Bytes written to the ring so far, and the last fence's value.
    wptr: u64,
    seq: u32,
    /// The GART's pages: mapped framebuffers (their buffers, first page
    /// and count) and the free runs.
    mapped: alloc::collections::BTreeMap<u32, (Arc<super::drm::Buffer>, u64, u64)>,
    /// The 2D requests' images (`drm::twod`): each image, its first page
    /// and count.
    images: alloc::collections::BTreeMap<u32, (Arc<super::drm::twod::Image>, u64, u64)>,
    free: Vec<(u64, u64)>,
    /// MEC1's queue, for the requests shaders do (none without GC's
    /// firmware: then blends are the CPU's).
    compute: Option<Compute>,
    gart_start: u64,
    /// What an entry holds with nothing mapped there.
    scratch_entry: u64,
    /// A copy didn't finish: the CPU copies from then on.
    broken: bool,
}

// SAFETY: the mappings are of the card's BAR, for the kernel's life;
// the engine is used under its lock.
unsafe impl Send for Engine {}

const RING_SIZE: u32 = 64 << 10;

impl Engine {
    /// The GFX hub's context 0 and SDMA0's ring, started; none without a
    /// GC (or with `slate.amd.copy=cpu`).
    fn start(gpu: &mut Gpu, bases: Bases) -> Option<Engine> {
        use slate_amdgpu::{gfxhub, sdma};
        let has = |w: &str| crate::boot::info().cmdline.split_ascii_whitespace().any(|x| x == w);
        if bases.gc0 == 0 || has("slate.amd.copy=cpu") {
            return None;
        }
        let v = gpu.vram;
        let layout = gfxhub::Layout {
            fb_start: v.gpu,
            fb_end: v.gpu + v.size - 1,
            fb_system: v.system,
            gart_start: GART.0,
            gart_end: GART.1,
            table: v.gpu + GART_TABLE_AT,
            scratch: v.gpu + SCRATCH_AT,
        };
        let pages = layout.entries();
        if GART_TABLE_AT + pages * 8 > SCRATCH_AT || SCRATCH_AT + 4096 > v.bar_size {
            return None;
        }
        // Every entry the scratch page's (valid) until something is mapped
        // there: SDMA reads past what it copies.
        let scratch = gfxhub::vram_entry(&layout, v.gpu + SCRATCH_AT).to_le_bytes();
        let mut chunk = alloc::vec![0u8; 4096];
        for e in chunk.chunks_mut(8) {
            e.copy_from_slice(&scratch);
        }
        for at in (0..pages * 8).step_by(4096) {
            v.write(GART_TABLE_AT + at, &chunk);
        }
        v.clear(SCRATCH_AT, 4096);
        v.clear(SDMA_AT, u64::from(RING_SIZE) + 4096);
        psp::Memory::flush(gpu);
        let mut card = Card(gpu.regs);
        gfxhub::enable(&mut card, bases.gc0, &layout);
        if !gfxhub::flush(&mut card, bases.gc0) {
            log_warn!("amd: the GFX hub didn't flush its TLBs; the CPU copies");
            return None;
        }
        let ring =
            sdma::Ring { address: v.gpu + SDMA_AT, size: RING_SIZE, rptr: v.gpu + SDMA_AT + u64::from(RING_SIZE) };
        sdma::start(&mut card, bases.gc0, &ring);
        let map = |at: u64, len: u64| crate::mm::vmap::map_wc(crate::mm::PhysAddr(v.bar_phys + at), len) as u64;
        let mut e = Engine {
            seg0: bases.gc0,
            hdp_flush: bases.hdp_flush,
            ring,
            ring_map: map(SDMA_AT, u64::from(RING_SIZE) + 4096),
            table_map: map(GART_TABLE_AT, pages * 8),
            wptr: 0,
            seq: 0,
            mapped: alloc::collections::BTreeMap::new(),
            images: alloc::collections::BTreeMap::new(),
            free: alloc::vec![(0, pages)],
            compute: None,
            gart_start: GART.0,
            scratch_entry: gfxhub::vram_entry(&layout, v.gpu + SCRATCH_AT),
            broken: false,
        };
        // A first fence, to know the ring runs.
        let regs = gpu.regs;
        if !e.run(regs, &[]) {
            log_warn!("amd: SDMA0 didn't take its first fence; the CPU copies");
            return None;
        }
        log_info!(
            "amd: SDMA0 copies for the card (a {} KiB ring, a {} MiB GART)",
            RING_SIZE >> 10,
            (pages * 4096) >> 20
        );
        if GC_LOADED.load(core::sync::atomic::Ordering::Relaxed) {
            e.compute = Compute::start(gpu, bases);
            log_info!("amd: compute for the card's 2D requests: {}", if e.compute.is_some() { "on" } else { "off" });
        }
        Some(e)
    }

    fn flush_hdp(&self, regs: &Mmio) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        regs.write32(self.hdp_flush, 0);
        regs.read32(RCC_CONFIG_MEMSIZE);
    }

    /// `packets`, then a fence, on the ring; whether the fence came within
    /// 50 ms (else the engine is given up).
    fn run(&mut self, regs: &Mmio, packets: &[u32]) -> bool {
        use slate_amdgpu::sdma;
        if self.broken {
            return false;
        }
        self.seq = self.seq.wrapping_add(1);
        let fence_at = self.ring.rptr + 64;
        let mut p = Vec::with_capacity(packets.len() + 16);
        p.extend_from_slice(packets);
        p.extend_from_slice(&sdma::fence(fence_at, self.seq));
        p.resize(p.len() + sdma::padding(p.len()), 0);
        let size = u64::from(self.ring.size);
        if p.len() as u64 * 4 > size / 2 {
            return false;
        }
        // Packets don't wrap: NOPs to the ring's end first.
        let at = self.wptr % size;
        if at + p.len() as u64 * 4 > size {
            for i in (at..size).step_by(4) {
                // SAFETY: inside the ring's mapping.
                unsafe { ((self.ring_map + i) as *mut u32).write_volatile(0) };
            }
            self.wptr += size - at;
        }
        let at = self.wptr % size;
        for (i, w) in p.iter().enumerate() {
            // SAFETY: inside the ring's mapping (checked above).
            unsafe { ((self.ring_map + at) as *mut u32).add(i).write_volatile(*w) };
        }
        self.flush_hdp(regs);
        self.wptr += p.len() as u64 * 4;
        sdma::kick(&mut Card(regs), self.seg0, self.wptr);
        let fence = (self.ring_map + u64::from(self.ring.size) + 64) as *const u32;
        let end = crate::time::monotonic_ns() + 50_000_000;
        // SAFETY: the fence is in the mapping, after the ring.
        while unsafe { fence.read_volatile() } != self.seq {
            if crate::time::monotonic_ns() > end {
                let (status, error) = sdma::status(&mut Card(regs), self.seg0);
                log_warn!(
                    "amd: SDMA0 didn't finish (status {status:#x}, error log {error:#x}); the CPU copies from now on"
                );
                self.broken = true;
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }

    /// `frames` into the GART, in order; their first page.
    fn map_pages(&mut self, regs: &Mmio, frames: &[crate::mm::PhysAddr]) -> Option<u64> {
        let n = frames.len() as u64;
        let k = self.free.iter().position(|&(_, len)| len >= n)?;
        let (first, len) = self.free[k];
        if len == n {
            self.free.remove(k);
        } else {
            self.free[k] = (first + n, len - n);
        }
        for (i, f) in frames.iter().enumerate() {
            let e = slate_amdgpu::gfxhub::system_entry(f.0);
            // SAFETY: entry `first + i` is inside the table's mapping.
            unsafe { ((self.table_map + (first + i as u64) * 8) as *mut u64).write_volatile(e) };
        }
        self.flush_hdp(regs);
        if !slate_amdgpu::gfxhub::flush(&mut Card(regs), self.seg0) {
            self.unmap_pages(regs, first, n);
            return None;
        }
        Some(first)
    }

    /// GART pages `first`.. `first + n` back (the engine is idle: each
    /// request is waited for), pointing at the scratch page.
    fn unmap_pages(&mut self, regs: &Mmio, first: u64, n: u64) {
        for i in 0..n {
            // SAFETY: inside the table's mapping.
            unsafe { ((self.table_map + (first + i) * 8) as *mut u64).write_volatile(self.scratch_entry) };
        }
        self.flush_hdp(regs);
        slate_amdgpu::gfxhub::flush(&mut Card(regs), self.seg0);
        self.free.push((first, n));
    }

    /// `fb`'s buffer in the GART (mapped the first time); its GPU address.
    fn map(&mut self, regs: &Mmio, fb: &Arc<super::drm::Framebuffer>) -> Option<u64> {
        if let Some((b, first, _)) = self.mapped.get(&fb.id)
            && Arc::ptr_eq(b, &fb.buffer)
        {
            return Some(self.gart_start + first * 4096);
        }
        self.forget(regs, fb.id);
        let first = self.map_pages(regs, fb.buffer.frames())?;
        self.mapped.insert(fb.id, (fb.buffer.clone(), first, fb.buffer.frames().len() as u64));
        Some(self.gart_start + first * 4096)
    }

    /// Framebuffer `id`'s GART pages back, its buffer let go.
    fn forget(&mut self, regs: &Mmio, id: u32) {
        if let Some((_, first, n)) = self.mapped.remove(&id) {
            self.unmap_pages(regs, first, n);
        }
    }

    /// Image `id`'s first pixel's GPU address, if it is mapped.
    fn image_at(&self, id: u32) -> Option<(u64, &super::drm::twod::Image)> {
        let (img, first, _) = self.images.get(&id)?;
        Some((self.gart_start + first * 4096 + u64::from(img.offset), img))
    }

    /// The copy packets for `size` pixels from `from` in `src` to `at` in
    /// `dst`: whole rows on both sides are one run of bytes (linear copies
    /// of up to `sdma::MAX_BYTES`); otherwise sub-window copies in bands
    /// of up to that many bytes. Each packet on its own.
    fn copy_packets(
        src: slate_amdgpu::sdma::Image,
        from: (u32, u32),
        dst: slate_amdgpu::sdma::Image,
        at: (u32, u32),
        size: (u32, u32),
    ) -> Vec<Vec<u32>> {
        use slate_amdgpu::sdma::{MAX_BYTES, copy as linear, copy_rect};
        let place = |pitch: u32, x: u32, y: u32| (u64::from(y) * u64::from(pitch) + u64::from(x)) * 4;
        let mut packets = Vec::new();
        if from.0 == 0 && at.0 == 0 && size.0 == src.pitch && src.pitch == dst.pitch {
            let (s0, d0) = (src.address + place(src.pitch, 0, from.1), dst.address + place(dst.pitch, 0, at.1));
            let total = u64::from(size.0) * u64::from(size.1) * 4;
            for off in (0..total).step_by(MAX_BYTES as usize) {
                packets.push(linear(s0 + off, d0 + off, u64::from(MAX_BYTES).min(total - off) as u32).to_vec());
            }
        } else {
            let band = (MAX_BYTES / (size.0 * 4)).max(1);
            for y in (0..size.1).step_by(band as usize) {
                let (f, t, rows) = ((from.0, from.1 + y), (at.0, at.1 + y), band.min(size.1 - y));
                packets.push(copy_rect(src, f, dst, t, (size.0, rows)).to_vec());
            }
        }
        packets
    }

    /// The fill packets for the `size` rectangle at `at` of `dst` with
    /// `value`: whole rows as one run, otherwise a fill a row.
    fn fill_packets(dst: slate_amdgpu::sdma::Image, at: (u32, u32), size: (u32, u32), value: u32) -> Vec<Vec<u32>> {
        use slate_amdgpu::sdma::{MAX_BYTES, fill};
        let row = |y: u32| dst.address + (u64::from(y) * u64::from(dst.pitch) + u64::from(at.0)) * 4;
        if at.0 == 0 && size.0 == dst.pitch {
            let total = u64::from(size.0) * u64::from(size.1) * 4;
            return (0..total)
                .step_by(MAX_BYTES as usize)
                .map(|off| fill(row(at.1) + off, value, u64::from(MAX_BYTES).min(total - off) as u32).to_vec())
                .collect();
        }
        (0..size.1).map(|y| fill(row(at.1 + y), value, size.0 * 4).to_vec()).collect()
    }

    /// `packets` on the ring, as many runs as it takes (each within half
    /// of it), each waited for.
    fn run_all(&mut self, regs: &Mmio, packets: &[Vec<u32>]) -> bool {
        let limit = self.ring.size as usize / 8 - 16;
        let mut run = Vec::new();
        for p in packets {
            if run.len() + p.len() > limit && !self.run(regs, &run) {
                return false;
            }
            if run.len() + p.len() > limit {
                run.clear();
            }
            run.extend_from_slice(p);
        }
        run.is_empty() || self.run(regs, &run)
    }

    /// Copy `size` pixels of `fb` from `from` to `at` in `dst`: whole rows
    /// on both sides are one run of bytes (linear copies of up to
    /// `sdma::MAX_BYTES`); otherwise sub-window copies, in bands of up to
    /// that many bytes.
    fn copy(
        &mut self,
        regs: &Mmio,
        fb: &Arc<super::drm::Framebuffer>,
        from: (u32, u32),
        dst: slate_amdgpu::sdma::Image,
        at: (u32, u32),
        size: (u32, u32),
    ) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        if self.broken || fb.pitch % 4 != 0 || fb.offset % 4 != 0 {
            return false;
        }
        let Some(base) = self.map(regs, fb) else { return false };
        let src =
            slate_amdgpu::sdma::Image { address: base + u64::from(fb.offset), pitch: fb.pitch / 4, height: fb.height };
        let packets = Self::copy_packets(src, from, dst, at, size);
        let ok = self.run_all(regs, &packets);
        if ok {
            COPIES.fetch_add(1, Relaxed)
        } else {
            COPY_FAILS.fetch_add(1, Relaxed)
        };
        ok
    }
}

/// MEC1's queue for the card's 2D requests (M32 phase 6, step 6, ADR
/// 0172's addendum): its MQD, end-of-pipe buffer, pointers and fence at
/// `COMPUTE_AT` (as `compute_test` has them), the shaders after them, and
/// a 64 KiB ring at 64 KiB in; each run fenced (RELEASE_MEM) and waited
/// for.
struct Compute {
    seg0: u32,
    hdp_flush: usize,
    ring_map: u64,
    page_map: u64,
    gpu: u64,
    wptr: u64,
    seq: u32,
}

const COMPUTE_RING_AT: u64 = 0x1_0000;
const COMPUTE_RING_SIZE: u32 = 64 << 10;
const BLEND_AT: u64 = 0x5000;
const BLEND_STRAIGHT_AT: u64 = 0x6000;

impl Compute {
    fn start(gpu: &mut Gpu, bases: Bases) -> Option<Compute> {
        use slate_amdgpu::cp;
        let v = gpu.vram;
        v.clear(COMPUTE_AT, COMPUTE_RING_AT + u64::from(COMPUTE_RING_SIZE));
        for (d, w) in cp::mqd() {
            v.write(COMPUTE_AT + 4 * d as u64, &w.to_le_bytes());
        }
        for (at, prog) in
            [(BLEND_AT, slate_amdgpu::rdna2::blend()), (BLEND_STRAIGHT_AT, slate_amdgpu::rdna2::blend_straight())]
        {
            let code: Vec<u8> = prog.iter().flat_map(|w| w.to_le_bytes()).collect();
            v.write(COMPUTE_AT + at, &code);
        }
        psp::Memory::flush(gpu);
        let base = v.gpu + COMPUTE_AT;
        let q = cp::Queue {
            mqd: base,
            eop: base + 0x1000,
            ring: base + COMPUTE_RING_AT,
            size: COMPUTE_RING_SIZE,
            rptr: base + 0x3000,
            wptr: base + 0x3008,
        };
        interp::Card::write(gpu, bases.gc0 + cp::reg::GRBM_GFX_CNTL, 0);
        interp::Card::write(gpu, bases.gc0 + cp::reg::SH_MEM_CONFIG, cp::SH_MEM_CONFIG);
        cp::start(gpu, bases.gc0, &q);
        let map = |at: u64, len: u64| crate::mm::vmap::map_wc(crate::mm::PhysAddr(v.bar_phys + at), len) as u64;
        let mut c = Compute {
            seg0: bases.gc0,
            hdp_flush: bases.hdp_flush,
            ring_map: map(COMPUTE_AT + COMPUTE_RING_AT, u64::from(COMPUTE_RING_SIZE)),
            page_map: map(COMPUTE_AT + 0x3000, 4096),
            gpu: base,
            wptr: 0,
            seq: 0,
        };
        c.run(gpu.regs, &[]).then_some(c)
    }

    /// `packets`, an ACQUIRE_MEM first and a RELEASE_MEM fence after, on
    /// the ring; whether the fence came within 50 ms.
    fn run(&mut self, regs: &Mmio, packets: &[u32]) -> bool {
        use slate_amdgpu::cp;
        self.seq = self.seq.wrapping_add(1);
        let mut p = Vec::with_capacity(packets.len() + 24);
        p.extend_from_slice(&cp::acquire_mem());
        p.extend_from_slice(packets);
        p.extend_from_slice(&cp::release_mem(self.gpu + 0x3040, self.seq));
        p.resize(p.len().next_multiple_of(8), cp::NOP);
        let size = u64::from(COMPUTE_RING_SIZE / 4);
        if p.len() as u64 > size / 2 {
            return false;
        }
        let at = self.wptr % size;
        if at + p.len() as u64 > size {
            for i in at..size {
                // SAFETY: inside the ring's mapping.
                unsafe { ((self.ring_map + 4 * i) as *mut u32).write_volatile(cp::NOP) };
            }
            self.wptr += size - at;
        }
        let at = self.wptr % size;
        for (i, w) in p.iter().enumerate() {
            // SAFETY: inside the ring's mapping (checked above).
            unsafe { ((self.ring_map + 4 * at) as *mut u32).add(i).write_volatile(*w) };
        }
        self.wptr += p.len() as u64;
        let flush = || {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            regs.write32(self.hdp_flush, 0);
            regs.read32(RCC_CONFIG_MEMSIZE);
        };
        flush();
        // SAFETY: the polled write pointer, at 8 in the pointers' page.
        unsafe { ((self.page_map + 8) as *mut u64).write_volatile(self.wptr) };
        flush();
        let end = crate::time::monotonic_ns() + 50_000_000;
        // SAFETY: the fence, at 40h in the pointers' page.
        while unsafe { ((self.page_map + 0x40) as *const u32).read_volatile() } != self.seq {
            if crate::time::monotonic_ns() > end {
                log_warn!("amd: the compute queue didn't finish (fence {})", self.seq);
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }

    /// Blend `size` pixels of `src` (premultiplied, or not with
    /// `straight`) over `dst`, both at their rectangles' top left, at
    /// opacity `k`.
    fn blend(
        &mut self,
        regs: &Mmio,
        src: (u64, u32),
        dst: (u64, u32),
        size: (u32, u32),
        k: f32,
        straight: bool,
    ) -> bool {
        use slate_amdgpu::{cp, rdna2};
        let user =
            [src.0 as u32, (src.0 >> 32) as u32, dst.0 as u32, (dst.0 >> 32) as u32, src.1, dst.1, size.0, k.to_bits()];
        let sh = cp::Shader {
            address: self.gpu + if straight { BLEND_STRAIGHT_AT } else { BLEND_AT },
            rsrc: cp::resources(12, 16, rdna2::BLEND_USER_SGPRS, true),
            threads: 64,
        };
        // The fence is `run`'s: this one's goes to a scratch dword.
        let p = cp::dispatch_packets(self.seg0, &sh, (size.0.div_ceil(64), size.1), &user, (self.gpu + 0x3080, 0));
        self.run(regs, &p)
    }
}

impl Engine {
    /// The 2D requests, in order, each done before the next.
    fn submit(&mut self, regs: &Mmio, ops: &[super::drm::twod::Request]) -> bool {
        use super::drm::twod;
        for (op, src, _) in ops {
            let Some((d, di)) = self.image_at(op.dst) else { return false };
            let dst = slate_amdgpu::sdma::Image { address: d, pitch: di.pitch / 4, height: di.height };
            let at = (op.dx as u32, op.dy as u32);
            let size = (op.w as u32, op.h as u32);
            let ok = match op.kind {
                twod::FILL => {
                    let p = Self::fill_packets(dst, at, size, op.value);
                    self.run_all(regs, &p)
                }
                twod::COPY | twod::BLEND | twod::BLEND_STRAIGHT if src.is_some() => {
                    let Some((s, si)) = self.image_at(op.src) else { return false };
                    let (sp, from) = (si.pitch, (op.sx as u32, op.sy as u32));
                    if op.kind == twod::COPY {
                        let src = slate_amdgpu::sdma::Image { address: s, pitch: sp / 4, height: si.height };
                        let p = Self::copy_packets(src, from, dst, at, size);
                        self.run_all(regs, &p)
                    } else {
                        let corner = |base: u64, pitch: u32, (x, y): (u32, u32)| {
                            base + u64::from(y) * u64::from(pitch) + u64::from(x) * 4
                        };
                        let (src_at, dst_at) = (corner(s, sp, from), corner(d, di.pitch, at));
                        let (dp, k) = (di.pitch, f32::from_bits(op.value));
                        match self.compute.as_mut() {
                            Some(c) => {
                                c.blend(regs, (src_at, sp), (dst_at, dp), size, k, op.kind == twod::BLEND_STRAIGHT)
                            }
                            None => false,
                        }
                    }
                }
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

impl super::drm::twod::TwoD for Hardware {
    fn image(&self, id: u32, image: &Arc<super::drm::twod::Image>) -> bool {
        let Some(engine) = &self.engine else { return false };
        let mut e = engine.lock();
        let Some(first) = e.map_pages(&self.regs, &image.frames) else { return false };
        e.images.insert(id, (image.clone(), first, image.frames.len() as u64));
        true
    }
    fn free(&self, id: u32) {
        let Some(engine) = &self.engine else { return };
        let mut e = engine.lock();
        if let Some((_, first, n)) = e.images.remove(&id) {
            e.unmap_pages(&self.regs, first, n);
        }
    }
    fn submit(&self, ops: &[super::drm::twod::Request]) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        let Some(engine) = &self.engine else { return false };
        let ok = engine.lock().submit(&self.regs, ops);
        if ok {
            TWOD.fetch_add(ops.len() as u64, Relaxed)
        } else {
            TWOD_FAILS.fetch_add(1, Relaxed)
        };
        ok
    }
}

/// Where M32 phase 6's step 2 works in the carve-out (offsets in BAR 0):
/// SDMA0's ring (4 KiB) with its read pointer's write-back and a fence
/// after it, the GART's table (1 GiB of 4 KiB pages: 2 MiB) and a
/// scratch page, and two 1 MiB buffers.
const SDMA_AT: u64 = 200 << 20;
const GART_TABLE_AT: u64 = 201 << 20;
const SCRATCH_AT: u64 = 203 << 20;
const SDMA_A_AT: u64 = 204 << 20;
const SDMA_B_AT: u64 = 206 << 20;
/// The GART's GPU addresses: 1 GiB from 0, as amdgpu places Raphael's.
const GART: (u64, u64) = (0, (1 << 30) - 1);

/// M32 phase 6, step 2 (ADR 0172): with `slate.amd.sdma`, the GFX hub's
/// context 0 over the carve-out, then SDMA0 on a ring there filling a
/// buffer, copying it to another, writing two words and a fence; what it
/// did, read back through BAR 0.
fn sdma_test(a: super::pci::Address, regs: &Mmio, vram: &Vram, table: &Table, hdp_flush: usize) {
    use slate_amdgpu::{gfxhub, sdma};
    if !crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.sdma") {
        return;
    }
    let Some(gc) = table.find(discovery::GC) else { return };
    let seg0 = gc.base[0] as u32;
    let mut card = Card(regs);
    let flush = || {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        regs.write32(hdp_flush, 0);
        regs.read32(RCC_CONFIG_MEMSIZE);
    };
    let fb = (
        interp::Card::read(&mut card, seg0 + gfxhub::reg::FB_LOCATION_BASE),
        interp::Card::read(&mut card, seg0 + gfxhub::reg::FB_OFFSET),
    );
    let layout = gfxhub::Layout {
        fb_start: vram.gpu,
        fb_end: vram.gpu + vram.size - 1,
        fb_system: vram.system,
        gart_start: GART.0,
        gart_end: GART.1,
        table: vram.gpu + GART_TABLE_AT,
        scratch: vram.gpu + SCRATCH_AT,
    };
    // An empty GART (every entry invalid: misses go to the scratch page).
    vram.clear(GART_TABLE_AT, layout.entries() * 8);
    vram.clear(SCRATCH_AT, 4096);
    vram.clear(SDMA_AT, 8192);
    flush();
    gfxhub::enable(&mut card, seg0, &layout);
    let flushed = gfxhub::flush(&mut card, seg0);
    let ring = sdma::Ring { address: vram.gpu + SDMA_AT, size: 4096, rptr: vram.gpu + SDMA_AT + 4096 };
    let fence_at = SDMA_AT + 4096 + 64;
    sdma::start(&mut card, seg0, &ring);
    let (a_gpu, b_gpu) = (vram.gpu + SDMA_A_AT, vram.gpu + SDMA_B_AT);
    const PATTERN: u32 = 0x5EED_C0DE;
    let mut p = alloc::vec::Vec::new();
    p.extend_from_slice(&sdma::fill(a_gpu, PATTERN, 1 << 20));
    p.extend_from_slice(&sdma::copy(a_gpu, b_gpu, 1 << 20));
    p.extend_from_slice(&sdma::write(b_gpu, &[0x1234_5678, 0x9ABC_DEF0]));
    p.extend_from_slice(&sdma::fence(vram.gpu + fence_at, 1));
    p.resize(p.len() + sdma::padding(p.len()), 0);
    let bytes: alloc::vec::Vec<u8> = p.iter().flat_map(|w| w.to_le_bytes()).collect();
    vram.write(SDMA_AT, &bytes);
    flush();
    let start = crate::time::monotonic_ns();
    sdma::kick(&mut card, seg0, bytes.len() as u64);
    let mut done = false;
    while crate::time::monotonic_ns() - start < 100_000_000 {
        if vram.read32(fence_at) == 1 {
            done = true;
            break;
        }
        core::hint::spin_loop();
    }
    let us = (crate::time::monotonic_ns() - start) / 1000;
    let filled = [0, (1 << 20) - 4].iter().all(|&o| vram.read32(SDMA_A_AT + o) == PATTERN);
    let copied = [8, 4096, (1 << 20) - 4].iter().all(|&o| vram.read32(SDMA_B_AT + o) == PATTERN);
    let written = (vram.read32(SDMA_B_AT), vram.read32(SDMA_B_AT + 4)) == (0x1234_5678, 0x9ABC_DEF0);
    let (status, error) = sdma::status(&mut card, seg0);
    log_info!(
        "amd {a:?}: SDMA0: fence {} after {us} us; filled {filled}, copied {copied}, written {written}; read pointer {:#x} \
         (written back {:#x}), status {status:#x}, error log {error:#x}, fault {:x?}, TLB flushed {flushed}, hub FB {:#x} offset {:#x}",
        if done { "came" } else { "didn't come" },
        interp::Card::read(&mut card, seg0 + sdma::reg::RB_RPTR),
        vram.read32(SDMA_AT + 4096),
        gfxhub::fault(&mut card, seg0),
        fb.0,
        fb.1
    );
    if done {
        sdma_gart_test(a, &mut card, seg0, vram, &layout, &ring, bytes.len() as u64, &flush);
        sdma_window_test(a, &mut card, seg0, vram, &ring, &flush);
    }
}

/// Bring-up: sub-window copies in the carve-out, every pixel checked. A
/// gradient (256 x 1024 pixels, 1 MiB) at A, copied to B (cleared) whole,
/// as a 100 x 50 rectangle from (10, 20) to (30, 40), and as the last ten
/// rows (to the image's end); how many pixels came out wrong in each.
fn sdma_window_test(
    a: super::pci::Address,
    card: &mut Card,
    seg0: u32,
    vram: &Vram,
    ring: &slate_amdgpu::sdma::Ring,
    flush: &dyn Fn(),
) {
    use slate_amdgpu::sdma;
    let (w, h) = (256u32, 1024u32);
    let px = |x: u32, y: u32| 0xC000_0000 | (y << 12) | x;
    let mut row = alloc::vec![0u8; (w * 4) as usize];
    for y in 0..h {
        for x in 0..w {
            row[(x * 4) as usize..(x * 4 + 4) as usize].copy_from_slice(&px(x, y).to_le_bytes());
        }
        vram.write(SDMA_A_AT + u64::from(y * w * 4), &row);
    }
    let img = |at: u64| sdma::Image { address: vram.gpu + at, pitch: w, height: h };
    // (from, to, size) each.
    type Pair = (u32, u32);
    let cases: [(Pair, Pair, Pair); 3] =
        [((0, 0), (0, 0), (w, h)), ((10, 20), (30, 40), (100, 50)), ((0, h - 10), (0, h - 10), (w, 10))];
    let mut wrong = [0u32; 3];
    for (k, &(from, to, size)) in cases.iter().enumerate() {
        vram.clear(SDMA_B_AT, u64::from(w * h * 4));
        flush();
        let fence_at = SDMA_AT + 4096 + 64;
        let mut p = alloc::vec::Vec::new();
        p.extend_from_slice(&sdma::copy_rect(img(SDMA_A_AT), from, img(SDMA_B_AT), to, size));
        p.extend_from_slice(&sdma::fence(vram.gpu + fence_at, 10 + k as u32));
        p.resize(p.len() + sdma::padding(p.len()), 0);
        let bytes: alloc::vec::Vec<u8> = p.iter().flat_map(|w| w.to_le_bytes()).collect();
        sdma::start(card, seg0, ring);
        vram.write(SDMA_AT, &bytes);
        flush();
        sdma::kick(card, seg0, bytes.len() as u64);
        let t = crate::time::monotonic_ns();
        while vram.read32(fence_at) != 10 + k as u32 && crate::time::monotonic_ns() - t < 100_000_000 {
            core::hint::spin_loop();
        }
        for y in 0..size.1 {
            for x in 0..size.0 {
                let at = SDMA_B_AT + u64::from(((to.1 + y) * w + to.0 + x) * 4);
                if vram.read32(at) != px(from.0 + x, from.1 + y) {
                    wrong[k] += 1;
                }
            }
        }
    }
    log_info!("amd {a:?}: SDMA0 sub-window copies (whole, inside, to the end): {wrong:?} pixels wrong");
}

/// Step 3: system memory through the GART. Four pages of RAM mapped at
/// the GART's start and four more after them; SDMA0 copies the first four
/// (a pattern the CPU wrote) into the carve-out, and buffer B (step 2's
/// pattern) into the other four, then fences; the CPU checks both.
#[allow(clippy::too_many_arguments)]
fn sdma_gart_test(
    a: super::pci::Address,
    card: &mut Card,
    seg0: u32,
    vram: &Vram,
    layout: &slate_amdgpu::gfxhub::Layout,
    ring: &slate_amdgpu::sdma::Ring,
    wptr: u64,
    flush: &dyn Fn(),
) {
    use slate_amdgpu::{gfxhub, sdma};
    const PAGES: u64 = 4;
    let (Some(from), Some(to)) = (crate::mm::frame::alloc(2), crate::mm::frame::alloc(2)) else { return };
    let len = (PAGES * 4096) as usize;
    // SAFETY: Both are new blocks of four frames, ours, in the direct map.
    let (src, dst) = unsafe {
        (
            core::slice::from_raw_parts_mut(from.to_virt().cast::<u32>(), len / 4),
            core::slice::from_raw_parts_mut(to.to_virt().cast::<u32>(), len / 4),
        )
    };
    for (i, w) in src.iter_mut().enumerate() {
        *w = 0xA000_0000 | i as u32;
    }
    dst.fill(0);
    // Their GART entries: the first four pages from the GART's start.
    for k in 0..2 * PAGES {
        let phys = if k < PAGES { from.0 + k * 4096 } else { to.0 + (k - PAGES) * 4096 };
        vram.write(GART_TABLE_AT + k * 8, &gfxhub::system_entry(phys).to_le_bytes());
    }
    flush();
    let flushed = gfxhub::flush(card, seg0);
    let c_at = SDMA_A_AT + (1 << 20) - len as u64 * 2;
    let (gart_src, gart_dst) = (layout.gart_start, layout.gart_start + PAGES * 4096);
    let fence_at = SDMA_AT + 4096 + 64;
    let mut p = alloc::vec::Vec::new();
    p.extend_from_slice(&sdma::copy(gart_src, vram.gpu + c_at, len as u32));
    p.extend_from_slice(&sdma::copy(vram.gpu + SDMA_B_AT + 4096, gart_dst, len as u32));
    p.extend_from_slice(&sdma::fence(vram.gpu + fence_at, 2));
    p.resize(p.len() + sdma::padding(p.len()), 0);
    let bytes: alloc::vec::Vec<u8> = p.iter().flat_map(|w| w.to_le_bytes()).collect();
    vram.write(SDMA_AT + wptr % u64::from(ring.size), &bytes);
    flush();
    let start = crate::time::monotonic_ns();
    sdma::kick(card, seg0, wptr + bytes.len() as u64);
    let mut done = false;
    while crate::time::monotonic_ns() - start < 100_000_000 {
        if vram.read32(fence_at) == 2 {
            done = true;
            break;
        }
        core::hint::spin_loop();
    }
    let us = (crate::time::monotonic_ns() - start) / 1000;
    // A rectangle: 37 x 5 pixels at (3, 2) of the first four pages (an
    // image 64 pixels square) to (10, 7) of one 128 pixels wide in the
    // carve-out, over a fill; its corners there, and the pixels just
    // outside it untouched.
    let d_at = SDMA_B_AT + (1 << 19);
    let src_img = sdma::Image { address: gart_src, pitch: 64, height: 64 };
    let dst_img = sdma::Image { address: vram.gpu + d_at, pitch: 128, height: 32 };
    let mut q = alloc::vec::Vec::new();
    q.extend_from_slice(&sdma::fill(vram.gpu + d_at, 0x0BAD_F00D, 128 * 32 * 4));
    q.extend_from_slice(&sdma::copy_rect(src_img, (3, 2), dst_img, (10, 7), (37, 5)));
    q.extend_from_slice(&sdma::fence(vram.gpu + fence_at, 3));
    q.resize(q.len() + sdma::padding(q.len()), 0);
    let more: alloc::vec::Vec<u8> = q.iter().flat_map(|w| w.to_le_bytes()).collect();
    let wptr = wptr + bytes.len() as u64;
    vram.write(SDMA_AT + wptr % u64::from(ring.size), &more);
    flush();
    sdma::kick(card, seg0, wptr + more.len() as u64);
    let t = crate::time::monotonic_ns();
    while vram.read32(fence_at) != 3 && crate::time::monotonic_ns() - t < 100_000_000 {
        core::hint::spin_loop();
    }
    let px = |x: u64, y: u64| vram.read32(d_at + 4 * (y * 128 + x));
    let s = |x: u32, y: u32| 0xA000_0000 | (y * 64 + x);
    let rect = [(10, 7, s(3, 2)), (46, 7, s(39, 2)), (10, 11, s(3, 6)), (46, 11, s(39, 6))]
        .iter()
        .all(|&(x, y, v)| px(x, y) == v)
        && [(9, 7), (47, 7), (10, 6), (10, 12), (47, 11), (46, 12)].iter().all(|&(x, y)| px(x, y) == 0x0BAD_F00D);
    log_info!(
        "amd {a:?}: SDMA0 sub-window copy: rectangle {rect} (corners {:x?}, outside {:x?})",
        [px(10, 7), px(46, 7), px(10, 11), px(46, 11)],
        [px(9, 7), px(47, 7), px(10, 6), px(10, 12)]
    );
    let into_vram = (0..len as u64 / 4).step_by(257).all(|i| vram.read32(c_at + 4 * i) == 0xA000_0000 | i as u32);
    // SAFETY: Reading what the GPU wrote (snooped) into our frames.
    let into_ram = (0..len / 4).step_by(257).all(|i| unsafe { core::ptr::read_volatile(&dst[i]) } == 0x5EED_C0DE);
    log_info!(
        "amd {a:?}: SDMA0 through the GART: fence {} after {us} us; RAM to the carve-out {into_vram}, the carve-out \
         to RAM {into_ram}; TLB flushed {flushed}, fault {:x?}, status {:#x}",
        if done { "came" } else { "didn't come" },
        gfxhub::fault(card, seg0),
        sdma::status(card, seg0).0
    );
    // A stale translation: GART page 100 read while it is invalid (the
    // scratch page's, or a fault to it), then mapped to the first page of
    // RAM above and the TLBs flushed, then read again.
    let probe = layout.gart_start + 100 * 4096;
    let e_at = SDMA_A_AT + (1 << 19);
    let mut stale = [0u32; 2];
    for (k, entry) in [None, Some(gfxhub::system_entry(from.0))].into_iter().enumerate() {
        if let Some(e) = entry {
            vram.write(GART_TABLE_AT + 100 * 8, &e.to_le_bytes());
            flush();
            gfxhub::flush(card, seg0);
        }
        let mut q = alloc::vec::Vec::new();
        q.extend_from_slice(&sdma::copy(probe, vram.gpu + e_at, 64));
        q.extend_from_slice(&sdma::fence(vram.gpu + fence_at, 20 + k as u32));
        q.resize(q.len() + sdma::padding(q.len()), 0);
        let b: alloc::vec::Vec<u8> = q.iter().flat_map(|w| w.to_le_bytes()).collect();
        sdma::start(card, seg0, ring);
        vram.write(SDMA_AT, &b);
        flush();
        sdma::kick(card, seg0, b.len() as u64);
        let t = crate::time::monotonic_ns();
        while vram.read32(fence_at) != 20 + k as u32 && crate::time::monotonic_ns() - t < 100_000_000 {
            core::hint::spin_loop();
        }
        stale[k] = vram.read32(e_at);
    }
    vram.write(GART_TABLE_AT + 100 * 8, &0u64.to_le_bytes());
    flush();
    gfxhub::flush(card, seg0);
    log_info!(
        "amd {a:?}: SDMA0 and a remapped GART page: before {:#x}, after {:#x} (RAM holds {:#x})",
        stale[0],
        stale[1],
        src[0]
    );
    // Kept if the engine may still write them.
    if done {
        crate::mm::frame::free(from, 2);
        crate::mm::frame::free(to, 2);
    }
}

/// Where M32 phase 6's compute bring-up works in the carve-out (offsets
/// in BAR 0): the queue's MQD, end-of-pipe buffer, 4 KiB ring, its read
/// and write pointers and a fence.
const COMPUTE_AT: u64 = 210 << 20;

/// M32 phase 6, step 5 (ADR 0172): with `slate.amd.compute` (and GC's
/// firmware loaded, `slate.amd.gcfw`), the GFX hub's context 0, MEC1's
/// queue 0 on a ring in the carve-out, and a WRITE_DATA on it; whether the
/// value came, and what the queue says.
fn compute_test(a: super::pci::Address, gpu: &mut Gpu, bases: Bases) {
    use slate_amdgpu::{cp, gfxhub};
    if !crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.compute") {
        return;
    }
    let v = gpu.vram;
    let layout = gfxhub::Layout {
        fb_start: v.gpu,
        fb_end: v.gpu + v.size - 1,
        fb_system: v.system,
        gart_start: GART.0,
        gart_end: GART.1,
        table: v.gpu + GART_TABLE_AT,
        scratch: v.gpu + SCRATCH_AT,
    };
    v.clear(GART_TABLE_AT, layout.entries() * 8);
    v.clear(COMPUTE_AT, 16 << 10);
    let q = cp::Queue {
        mqd: v.gpu + COMPUTE_AT,
        eop: v.gpu + COMPUTE_AT + 0x1000,
        ring: v.gpu + COMPUTE_AT + 0x2000,
        size: 4096,
        rptr: v.gpu + COMPUTE_AT + 0x3000,
        wptr: v.gpu + COMPUTE_AT + 0x3008,
    };
    for (d, w) in cp::mqd() {
        v.write(COMPUTE_AT + 4 * d as u64, &w.to_le_bytes());
    }
    psp::Memory::flush(gpu);
    gfxhub::enable(gpu, bases.gc0, &layout);
    gfxhub::flush(gpu, bases.gc0);
    let started = cp::start(gpu, bases.gc0, &q);
    let fence = COMPUTE_AT + 0x3040;
    let p = cp::write_data(v.gpu + fence, 0x600D_CAFE);
    let bytes: Vec<u8> = p.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.write(COMPUTE_AT + 0x2000, &bytes);
    psp::Memory::flush(gpu);
    // The write pointer, in dwords, where the MEC polls it.
    v.write(COMPUTE_AT + 0x3008, &(p.len() as u64).to_le_bytes());
    psp::Memory::flush(gpu);
    let start = crate::time::monotonic_ns();
    while v.read32(fence) != 0x600D_CAFE && crate::time::monotonic_ns() - start < 100_000_000 {
        core::hint::spin_loop();
    }
    let us = (crate::time::monotonic_ns() - start) / 1000;
    let regs = gpu.regs;
    let r = |reg: u32| regs.read32((bases.gc0 + reg) as usize * 4);
    interp::Card::write(gpu, bases.gc0 + cp::reg::GRBM_GFX_CNTL, cp::MEC1_PIPE0_QUEUE0);
    let (active, rptr, wptr) = (r(cp::reg::CP_HQD_ACTIVE), r(cp::reg::CP_HQD_PQ_RPTR), r(cp::reg::CP_HQD_PQ_WPTR_LO));
    interp::Card::write(gpu, bases.gc0 + cp::reg::GRBM_GFX_CNTL, 0);
    log_info!(
        "amd {a:?}: compute: MEC1 queue 0 {started:x?}; WRITE_DATA {} after {us} us; queue active {active:#x}, read \
         pointer {rptr:#x} (reported {:#x}), write pointer {wptr:#x}; CP_STAT {:#x}, MEC_CNTL {:#x}, GRBM_STATUS {:#x}",
        if v.read32(fence) == 0x600D_CAFE { "came" } else { "didn't come" },
        v.read32(COMPUTE_AT + 0x3000),
        r(0xF40),
        r(cp::reg::CP_MEC_CNTL),
        r(0xDA4)
    );
    let gc1 = |reg: u32| regs.read32((bases.gc1 + reg) as usize * 4);
    log_info!(
        "amd {a:?}: compute: MEC1's instruction pointer {:#x} then {:#x}, CPC status {:#x} busy {:#x} stalled {:#x}, \
         RLC_STAT {:#x}",
        r(0xF48),
        r(0xF48),
        r(0xE24),
        r(0xE25),
        r(0xE26),
        gc1(0x4C04)
    );
    if v.read32(fence) != 0x600D_CAFE {
        return;
    }
    // A first shader (`slate_amdgpu::rdna2::fill`): 16 groups of 64
    // threads fill 4 KiB with a value, over a buffer marked first; then
    // a RELEASE_MEM fence.
    let shader_at = COMPUTE_AT + 0x4000;
    let buffer_at = COMPUTE_AT + (1 << 20);
    let code: Vec<u8> = slate_amdgpu::rdna2::fill().iter().flat_map(|w| w.to_le_bytes()).collect();
    v.write(shader_at, &code);
    for i in 0..2048u64 {
        v.write(buffer_at + 4 * i, &0xDEAD_BEEFu32.to_le_bytes());
    }
    // SH_MEM_CONFIG for VMID 0 (selected: ME 0, pipe 0, VMID 0).
    interp::Card::write(gpu, bases.gc0 + cp::reg::GRBM_GFX_CNTL, 0);
    interp::Card::write(gpu, bases.gc0 + cp::reg::SH_MEM_CONFIG, cp::SH_MEM_CONFIG);
    psp::Memory::flush(gpu);
    let sh = cp::Shader { address: v.gpu + shader_at, rsrc: cp::resources(3, 8, 3, false), threads: 64 };
    let buf = v.gpu + buffer_at;
    let p2 = cp::dispatch_packets(
        bases.gc0,
        &sh,
        (16, 1),
        &[buf as u32, (buf >> 32) as u32, 0x5EED_0FF5],
        (v.gpu + fence, 2),
    );
    let bytes: Vec<u8> = p2.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.write(COMPUTE_AT + 0x2000 + 4 * p.len() as u64, &bytes);
    psp::Memory::flush(gpu);
    v.write(COMPUTE_AT + 0x3008, &((p.len() + p2.len()) as u64).to_le_bytes());
    psp::Memory::flush(gpu);
    let start = crate::time::monotonic_ns();
    while v.read32(fence) != 2 && crate::time::monotonic_ns() - start < 100_000_000 {
        core::hint::spin_loop();
    }
    let us = (crate::time::monotonic_ns() - start) / 1000;
    let filled = (0..1024).filter(|&i| v.read32(buffer_at + 4 * i) == 0x5EED_0FF5).count();
    let beyond = (1024..2048).filter(|&i| v.read32(buffer_at + 4 * i) == 0xDEAD_BEEF).count();
    log_info!(
        "amd {a:?}: compute: the fill shader's fence {} after {us} us; {filled} of 1024 dwords filled, {beyond} of 1024 \
         after them untouched; CP_STAT {:#x}, GRBM_STATUS {:#x}",
        if v.read32(fence) == 2 { "came" } else { "didn't come" },
        r(0xF40),
        r(0xDA4)
    );
    if v.read32(fence) != 2 {
        return;
    }
    // The blend (`rdna2::blend`): a 200 x 50 rectangle at (5, 2) of a
    // 256 x 64 source over a destination, at opacity 0.75, each pixel
    // checked against the CPU's `rdna2::blend_pixel`, and those around it
    // left alone.
    let blend_at = shader_at + 0x1000;
    let code: Vec<u8> = slate_amdgpu::rdna2::blend().iter().flat_map(|w| w.to_le_bytes()).collect();
    v.write(blend_at, &code);
    let (src_at, dst_at, pitch) = (COMPUTE_AT + (2 << 20), COMPUTE_AT + (3 << 20), 1024u32);
    let sp = |x: u32, y: u32| {
        let a = (x * 7 + y * 13) & 0xFF;
        let pm = |c: u32| (c * a + 127) / 255;
        (a << 24) | (pm((x * 3) & 0xFF) << 16) | (pm((y * 4) & 0xFF) << 8) | pm(0x80)
    };
    let dp = |x: u32, y: u32| 0xFF00_0000 | (((x + y) & 0xFF) << 16) | 0x8040;
    let mut row = alloc::vec![0u8; pitch as usize];
    for (at, px) in [(src_at, &sp as &dyn Fn(u32, u32) -> u32), (dst_at, &dp)] {
        for y in 0..64 {
            for x in 0..256 {
                row[(4 * x) as usize..(4 * x + 4) as usize].copy_from_slice(&px(x, y).to_le_bytes());
            }
            v.write(at + u64::from(y * pitch), &row);
        }
    }
    psp::Memory::flush(gpu);
    let k = 0.75f32;
    let origin = |at: u64| v.gpu + at + u64::from(2 * pitch + 5 * 4);
    let (sa, da) = (origin(src_at), origin(dst_at));
    let user = [sa as u32, (sa >> 32) as u32, da as u32, (da >> 32) as u32, pitch, pitch, 200, k.to_bits()];
    let rsrc = cp::resources(12, 16, slate_amdgpu::rdna2::BLEND_USER_SGPRS, true);
    let sh = cp::Shader { address: v.gpu + blend_at, rsrc, threads: 64 };
    let p3 = cp::dispatch_packets(bases.gc0, &sh, (4, 50), &user, (v.gpu + fence, 3));
    let bytes: Vec<u8> = p3.iter().flat_map(|w| w.to_le_bytes()).collect();
    let before = (p.len() + p2.len()) as u64;
    v.write(COMPUTE_AT + 0x2000 + 4 * before, &bytes);
    psp::Memory::flush(gpu);
    v.write(COMPUTE_AT + 0x3008, &(before + p3.len() as u64).to_le_bytes());
    psp::Memory::flush(gpu);
    let start = crate::time::monotonic_ns();
    while v.read32(fence) != 3 && crate::time::monotonic_ns() - start < 100_000_000 {
        core::hint::spin_loop();
    }
    let us = (crate::time::monotonic_ns() - start) / 1000;
    let (mut wrong, mut first) = (0u32, None);
    for y in 0..64 {
        for x in 0..256 {
            let inside = (5..205).contains(&x) && (2..52).contains(&y);
            let want = if inside { slate_amdgpu::rdna2::blend_pixel(sp(x, y), dp(x, y), k) } else { dp(x, y) };
            let got = v.read32(dst_at + u64::from(y * pitch + 4 * x));
            if got != want {
                wrong += 1;
                first.get_or_insert((x, y, got, want));
            }
        }
    }
    log_info!(
        "amd {a:?}: compute: the blend's fence {} after {us} us; {wrong} of 16384 pixels differ from the CPU's (the first \
         {first:x?})",
        if v.read32(fence) == 3 { "came" } else { "didn't come" }
    );
}

/// Bring-up: with `slate.amd.dump`, the registers of the blocks a plane
/// goes through (the DCCG's clocks, the hub, HUBP0, the DPP, MPCC0),
/// printed as `dump` does. Reading every register disturbs the hardware;
/// these blocks don't.
fn dump_plane(regs: &Mmio, seg1: u64, seg2: u64, seg3: u64) {
    if !crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.dump") {
        return;
    }
    let ranges = [
        (1, seg1, 0x70u64, 0xC0u64),
        (2, seg2, 0x80, 0x94),
        (2, seg2, 0x4A0, 0x500),
        (2, seg2, 0x5E0, 0x6A0),
        (2, seg2, 0xCC0, 0xD40),
        (2, seg2, 0x520, 0x540),
        (2, seg2, 0x1AC0, 0x1BA0),
        (3, seg3, 0, 0x10),
    ];
    for (seg, base, from, to) in ranges {
        let mut line = alloc::string::String::new();
        for w in from..to {
            let v = regs.read32((base + w) as usize * 4);
            if v != 0 {
                line += &alloc::format!(" {seg}:{w:x}={v:x}");
            }
            if line.len() > 200 || (w == to - 1 && !line.is_empty()) {
                kprintln!("amd-dump{line}");
                line.clear();
            }
        }
    }
}

/// The memory hub's view of the GPU's memory, given to the display engine,
/// and BAR 0 checked against it (step 5).
fn find_vram(pci: &Device, regs: &Mmio, table: &Table, dcn_seg2: u64, memsize: u32) -> Option<Vram> {
    let a = pci.address;
    let Some(mmhub) = table.find(discovery::MMHUB) else {
        log_warn!("amd {a:?}: no memory hub in the IP discovery table");
        return None;
    };
    let hub = |reg: u64| (mmhub.base[MMHUB_SEGMENT] + reg) as usize * 4;
    let dcn = |reg: u64| (dcn_seg2 + reg) as usize * 4;
    let (base, top, offset) = (
        regs.read32(hub(MMHUB_FB_BASE)) & FB_FIELD,
        regs.read32(hub(MMHUB_FB_TOP)) & FB_FIELD,
        regs.read32(hub(MMHUB_FB_OFFSET)) & FB_FIELD,
    );
    let size = (u64::from(top.wrapping_sub(base)) + 1) << 24;
    if top < base || size != u64::from(memsize) << 20 {
        log_warn!("amd {a:?}: the memory hub places {base:#x} to {top:#x}, not {memsize} MiB");
        return None;
    }
    let had = [DCN_FB_BASE, DCN_FB_TOP, DCN_FB_OFFSET].map(|r| regs.read32(dcn(r)) & FB_FIELD);
    if had != [base, top, offset] {
        log_info!("amd {a:?}: the display engine's view of memory was {had:x?}; given the memory hub's");
        regs.write32(dcn(DCN_FB_BASE), base);
        regs.write32(dcn(DCN_FB_TOP), top);
        regs.write32(dcn(DCN_FB_OFFSET), offset);
    }
    let Some(Bar::Memory { address: bar_phys, size: bar_size, .. }) = pci.bars[0] else {
        log_warn!("amd {a:?}: no BAR 0");
        return None;
    };
    let vram = Vram {
        gpu: u64::from(base) << 24,
        size,
        system: u64::from(offset) << 24,
        bar: pci.map_bar(0)?,
        bar_size: bar_size.min(size),
        bar_phys,
    };
    // A word written through BAR 0 reads back through MM_INDEX/MM_DATA
    // at the same offset, and the word that was there goes back.
    let mut was = [0u8; 4];
    read_vram(regs, PROBE_AT, &mut was);
    let mark = 0x5A7E_0171u32 ^ (PROBE_AT as u32);
    let mut seen = [0u8; 4];
    if vram.write(PROBE_AT, &mark.to_le_bytes()) {
        read_vram(regs, PROBE_AT, &mut seen);
        vram.write(PROBE_AT, &was);
    }
    if u32::from_le_bytes(seen) != mark {
        log_warn!("amd {a:?}: BAR 0 doesn't show the GPU's memory ({:#x} read back)", u32::from_le_bytes(seen));
        return None;
    }
    log_info!(
        "amd {a:?}: memory: {} MiB at GPU {:#x}, system {:#x}; BAR 0 shows {} MiB",
        vram.size >> 20,
        vram.gpu,
        vram.system,
        vram.bar_size >> 20
    );
    Some(vram)
}

/// Read `out.len()` bytes of the GPU's memory from `at` (four at a time).
fn read_vram(regs: &Mmio, at: u64, out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(4).enumerate() {
        let pos = at + 4 * i as u64;
        regs.write32(MM_INDEX, (pos as u32 & 0x7FFF_FFFF) | 0x8000_0000);
        regs.write32(MM_INDEX_HI, (pos >> 31) as u32);
        let v = regs.read32(MM_DATA).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

/// The VBIOS for `pci` in the VFCT table: by its address, else (a guest,
/// whose addresses aren't the host's) by its IDs.
fn vbios(pci: &Device) -> Option<&'static [u8]> {
    let t = crate::acpi::info().tables.iter().find(|t| &t.signature == b"VFCT")?.bytes;
    let a = pci.address;
    slate_amdgpu::vfct::vbios(t, a.bus.into(), a.device.into(), a.function.into(), pci.vendor, pci.device).or_else(
        || slate_amdgpu::vfct::images(t).find(|i| (i.vendor, i.device_id) == (pci.vendor, pci.device)).map(|i| i.image),
    )
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let a = pci.address;
    let regs = Mmio(pci.map_bar(5)?);
    let memsize = regs.read32(RCC_CONFIG_MEMSIZE);
    if memsize == 0 || memsize == u32::MAX {
        log_warn!("amd {a:?}: no memory size ({memsize:#x}); not this card's display");
        return None;
    }
    let mut bin = alloc::vec![0u8; discovery::SIZE];
    read_vram(&regs, discovery::offset(memsize), &mut bin);
    let table = match Table::new(&bin) {
        Ok(t) => t,
        Err(e) => {
            log_warn!("amd {a:?}: {memsize} MiB, no IP discovery table ({e:?})");
            return None;
        }
    };
    let Some(dmu) = table.find(discovery::DMU) else {
        log_warn!("amd {a:?}: no display engine in the IP discovery table");
        return None;
    };
    let gc = table.find(discovery::GC).map_or((0, 0, 0), |g| g.version);
    log_info!(
        "amd {a:?}: {:04x}:{:04x}, {memsize} MiB, DCN {}.{}.{}, GC {}.{}.{}",
        pci.vendor,
        pci.device,
        dmu.version.0,
        dmu.version.1,
        dmu.version.2,
        gc.0,
        gc.1,
        gc.2
    );
    let image = vbios(&pci);
    let Some(rom) = image.and_then(Rom::new) else {
        log_warn!("amd {a:?}: no VBIOS in the ACPI VFCT table");
        return None;
    };
    log_info!("amd {a:?}: VBIOS {:?}", rom.build().unwrap_or("?"));
    let hpd = |pin: u8, reg: u64| (dmu.base[HPD_SEGMENT] + reg + HPD_STRIDE * u64::from(pin - 1)) as usize * 4;
    let paths: Vec<_> = rom.display_paths().collect();
    // The HPD blocks on (as amdgpu leaves them); they sense after their
    // connection timer.
    for p in &paths {
        if let Some(pin @ 1..=6) = p.hpd {
            regs.write32(hpd(pin, HPD_CONTROL), HPD_ON);
        }
    }
    delay_ms(20);
    let mut counts = [0u32; 3];
    let mut modes = alloc::vec![None; paths.len()];
    let mut monitors: Vec<Option<Monitor>> = alloc::vec![None; paths.len()];
    for (i, p) in paths.iter().enumerate() {
        let (prefix, n) = match p.kind {
            Connector::Hdmi => ("HDMI-A", &mut counts[0]),
            Connector::DisplayPort | Connector::UsbC => ("DP", &mut counts[1]),
            _ => ("eDP", &mut counts[2]),
        };
        *n += 1;
        let name = alloc::format!("{prefix}-{n}");
        let sensed = match p.hpd {
            Some(pin @ 1..=6) => regs.read32(hpd(pin, HPD_INT_STATUS)) & HPD_SENSE != 0,
            _ => false,
        };
        let phy = transmitter(p.encoder).map_or('?', |t| (b'A' + t) as char);
        log_info!(
            "amd {a:?}: {name} on PHY {phy}, HPD {:?}, DDC {:#x}: {}",
            p.hpd,
            p.ddc.unwrap_or(0),
            if sensed { "connected" } else { "nothing connected" }
        );
        // Bring-up without a monitor (M32 phase 6, ADR 0172): with
        // `slate.amd.force`, the first HDMI output is lit at CTA-861's
        // 1920x1080 at 60 Hz (VIC 16) with nothing there, so that the
        // card, its flips and its copies can be tried and read back.
        if !sensed
            && p.kind == Connector::Hdmi
            && counts[0] == 1
            && crate::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.amd.force")
        {
            log_info!("amd {a:?}: {name}: nothing there; lit at 1920x1080 at 60 Hz anyway (slate.amd.force)");
            modes[i] = Some(VIC16);
        }
        // HDMI's EDID over its DDC line, through the display engine's I2C
        // engine (DisplayPort's comes over AUX).
        if sensed && p.kind == Connector::Hdmi {
            let ddc = p.ddc.and_then(|id| Ddc::new(dmu.base[1] as u32, dmu.base[2] as u32, id & 0xF));
            if let Some(ddc) = ddc
                && let Some((t, m)) = report_edid(a, &name, ddc.edid(&mut Card(&regs)))
            {
                modes[i] = Some(t);
                monitors[i] = Some(m);
            }
        }
    }
    gc_report(a, &regs, &table);
    let vram = find_vram(&pci, &regs, &table, dmu.base[2], memsize)?;
    let Some(name) = dmcub_file(dmu.version) else {
        log_info!("amd {a:?}: no DMCUB firmware is known for this display engine");
        return Some(());
    };
    let (Some(mp0), Some(nbif)) = (table.find(discovery::MP0), table.find(discovery::NBIF)) else {
        log_warn!("amd {a:?}: no PSP or NBIF in the IP discovery table");
        return Some(());
    };
    let bases = Bases {
        gc0: table.find(discovery::GC).map_or(0, |g| g.base[0] as u32),
        gc1: table.find(discovery::GC).map_or(0, |g| g.base[1] as u32),
        nbio0: nbif.base[0] as u32,
        dcn1: dmu.base[1] as u32,
        dcn3: dmu.base[3] as u32,
        dcn2: dmu.base[2] as u32,
        mp0: mp0.base[0] as u32,
        hdp_flush: (nbif.base[NBIF_HDP_SEGMENT] + HDP_FLUSH) as usize * 4,
    };
    sdma_test(a, &regs, &vram, &table, bases.hdp_flush);
    let image = image.unwrap_or(&[]);
    let links: Vec<Link> = paths
        .iter()
        .zip(&modes)
        .filter_map(|(p, &mode)| {
            let link = mode::Link {
                phy: transmitter(p.encoder)?,
                connector: p.connector.id,
                encoder: p.encoder.id,
                hpd: p.hpd.unwrap_or(0),
            };
            Some(Link { link, mode })
        })
        .collect();
    // The links' monitors, in the same order (paths without a PHY have
    // no link).
    let monitors: Vec<Option<Monitor>> =
        paths.iter().zip(monitors).filter(|(p, _)| transmitter(p.encoder).is_some()).map(|(_, m)| m).collect();
    let outputs = Outputs { links, monitors, sys: super::pci_sys::path(pci.address) };
    super::firmware::request(name, move |bin| start_dmcub(a, &regs, &vram, bases, image, &outputs, bin));
    Some(())
}
