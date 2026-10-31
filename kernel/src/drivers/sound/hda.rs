// SPDX-License-Identifier: MIT OR Apache-2.0

//! HD Audio controllers (PCI class 04h/03h; ADR 0184).
//!
//! Source: Intel's High Definition Audio Specification, revision 1.0a
//! (2010): §3.3 the controller's registers (GCAP 00h, GCTL 08h, STATESTS
//! 0Eh, INTCTL 20h, INTSTS 24h, the CORB at 40h-4Eh, the RIRB at 50h-5Eh,
//! DPLBASE 70h, stream descriptors from 80h, 20h each: CTL 0-2, STS 3,
//! LPIB 4, CBL 8, LVI 0Ch, FMT 12h, BDPL 18h, BDPU 1Ch); §4.2-4.4 reset,
//! codec discovery and the command ring; §3.6 the buffer descriptor list.
//!
//! One card per controller, with one PCM device: playback from the first
//! codec's chosen DAC to all its analog outputs, capture from its chosen
//! input (`slate_hda::graph::plan`). Commands go through the CORB and come
//! back through the RIRB, polled (never sleeping, so streams can be set up
//! with their lock held). Each period is one or more buffer descriptors
//! (the buffer's pages may be scattered) whose last interrupts.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use slate_alsa::abi::*;
use slate_alsa::params::{Hardware, Interval, Mask, Setup, alloc_free::Rates};
use slate_hda::graph::{self, Codec, Graph, Path, Plan};
use slate_hda::verb::*;
use slate_sync::Once;

use super::control::{Elem, ElemOps, Kind};
use super::pcm::{Pages, PcmOps, Substream};
use crate::abi::linux::errno::*;
use crate::drivers::dma::{Dma, Mmio};
use crate::drivers::pci::Device;
use crate::fs::vfs::Result;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

const GCAP: usize = 0x00;
const GCTL: usize = 0x08;
const GCTL_CRST: u32 = 1 << 0;
const STATESTS: usize = 0x0E;
const INTCTL: usize = 0x20;
const INTCTL_GIE: u32 = 1 << 31;
const INTSTS: usize = 0x24;
const CORBLBASE: usize = 0x40;
const CORBUBASE: usize = 0x44;
const CORBWP: usize = 0x48;
const CORBRP: usize = 0x4A;
const CORBRP_RST: u16 = 1 << 15;
const CORBCTL: usize = 0x4C;
const CORBCTL_RUN: u8 = 1 << 1;
const CORBSIZE: usize = 0x4E;
const RIRBLBASE: usize = 0x50;
const RIRBUBASE: usize = 0x54;
const RIRBWP: usize = 0x58;
const RIRBWP_RST: u16 = 1 << 15;
const RINTCNT: usize = 0x5A;
const RIRBCTL: usize = 0x5C;
const RIRBCTL_DMAEN: u8 = 1 << 1;
const RIRBSTS: usize = 0x5D;
const RIRBSIZE: usize = 0x5E;
const DPLBASE: usize = 0x70;
const DPUBASE: usize = 0x74;
const SD_BASE: usize = 0x80;
const SD_SIZE: usize = 0x20;
const SD_CTL: usize = 0x00;
const SD_CTL_SRST: u32 = 1 << 0;
const SD_CTL_RUN: u32 = 1 << 1;
const SD_CTL_IOCE: u32 = 1 << 2;
const SD_STS: usize = 0x03;
/// SDnSTS: buffer completion, FIFO error, descriptor error (write 1 to
/// clear).
const SD_STS_CLEAR: u8 = 0x1C;
const SD_LPIB: usize = 0x04;
const SD_CBL: usize = 0x08;
const SD_LVI: usize = 0x0C;
const SD_FMT: usize = 0x12;
const SD_BDPL: usize = 0x18;
const SD_BDPU: usize = 0x1C;

/// Ring sizes: 256 entries each (CORBSIZE/RIRBSIZE value 2).
const RING_ENTRIES: u16 = 256;
/// A buffer is at most this big (the descriptor list holds 256 entries).
const BUFFER_MAX: u32 = 512 * 1024;

/// The command rings.
struct Rings {
    corb: Dma,
    rirb: Dma,
    corb_wp: u16,
    rirb_rp: u16,
}

pub struct Hda {
    name: String,
    regs: Mmio,
    rings: IrqSpinLock<Rings>,
    streams: IrqSpinLock<Vec<Arc<HdaStream>>>,
}

impl Hda {
    fn sd(&self, index: usize, reg: usize) -> usize {
        SD_BASE + index * SD_SIZE + reg
    }

    /// Run a verb and wait (spinning, up to 5 ms) for its response.
    fn command(&self, verb: u32) -> Option<u32> {
        let cad = verb >> 28;
        let mut r = self.rings.lock();
        let wp = (r.corb_wp + 1) % RING_ENTRIES;
        r.corb.write::<u32>(usize::from(wp) * 4, verb);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.regs.write16(CORBWP, wp);
        r.corb_wp = wp;
        let deadline = crate::time::monotonic_ns() + 5_000_000;
        loop {
            let hw = self.regs.read16(RIRBWP) & 0xff;
            while r.rirb_rp != hw {
                r.rirb_rp = (r.rirb_rp + 1) % RING_ENTRIES;
                let at = usize::from(r.rirb_rp) * 8;
                let resp = r.rirb.read::<u32>(at);
                let ext = r.rirb.read::<u32>(at + 4);
                // Unsolicited responses (bit 4) are not answers.
                if ext & 0x10 == 0 && ext & 0xf == cad {
                    self.regs.write8(RIRBSTS, 0x5);
                    return Some(resp);
                }
            }
            if crate::time::monotonic_ns() > deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }

    fn interrupt(&self) {
        let sts = self.regs.read32(INTSTS);
        if sts == 0 || sts == u32::MAX {
            return;
        }
        let streams = self.streams.lock().clone();
        for s in streams {
            if sts & (1 << s.index) != 0 {
                let off = self.sd(s.index, SD_STS);
                let v = self.regs.read8(off);
                self.regs.write8(off, v & SD_STS_CLEAR);
                if let Some(sub) = s.sub.get().and_then(Weak::upgrade) {
                    sub.period_elapsed();
                }
            }
        }
        // Responses are polled; clear the RIRB's status anyway.
        self.regs.write8(RIRBSTS, 0x5);
    }
}

/// Commands to a codec through the controller.
struct Link<'a>(&'a Hda);

impl Codec for Link<'_> {
    fn cmd(&mut self, verb: u32) -> Option<u32> {
        self.0.command(verb)
    }
}

/// A stream descriptor and the converter it feeds or is fed by.
pub struct HdaStream {
    hda: Arc<Hda>,
    /// The descriptor's index (input descriptors first).
    index: usize,
    tag: u8,
    cad: u8,
    conv: u8,
    hw: Hardware,
    /// The converter's sample size for 32-bit formats (24 or 32).
    bits32: u32,
    bdl: Dma,
    frame_bytes: AtomicU32,
    sub: Once<Weak<Substream>>,
}

impl HdaStream {
    fn reg(&self, r: usize) -> usize {
        self.hda.sd(self.index, r)
    }

    fn reset(&self) {
        let ctl = self.reg(SD_CTL);
        let regs = &self.hda.regs;
        regs.write32(ctl, regs.read32(ctl) & !(SD_CTL_RUN | SD_CTL_IOCE));
        regs.write32(ctl, regs.read32(ctl) | SD_CTL_SRST);
        spin_until(1_000_000, || regs.read32(ctl) & SD_CTL_SRST != 0);
        regs.write32(ctl, regs.read32(ctl) & !SD_CTL_SRST);
        spin_until(1_000_000, || regs.read32(ctl) & SD_CTL_SRST == 0);
    }
}

/// Spin until `cond` or `ns` pass.
fn spin_until(ns: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = crate::time::monotonic_ns() + ns;
    while !cond() {
        if crate::time::monotonic_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

impl PcmOps for HdaStream {
    fn hardware(&self) -> Hardware {
        self.hw.clone()
    }

    fn prepare(&self, s: &Setup, buf: &Arc<Pages>) -> Result<()> {
        let bits = if s.sample_bits == 32 { self.bits32 } else { s.sample_bits };
        let fmt = stream_format(s.rate, bits, s.channels).ok_or(EINVAL)?;
        self.reset();
        // The descriptor list: each period split at page boundaries, the
        // last piece of each period interrupting.
        let page = crate::mm::PAGE_SIZE as usize;
        let frames = buf.frames();
        let period = s.period_bytes();
        let mut n = 0usize;
        for p in 0..s.periods as usize {
            let (mut at, end) = (p * period, (p + 1) * period);
            while at < end {
                let len = (page - at % page).min(end - at);
                if n == 256 {
                    return Err(EINVAL);
                }
                let addr = frames[at / page].0 + (at % page) as u64;
                self.bdl.write::<u64>(n * 16, addr);
                self.bdl.write::<u32>(n * 16 + 8, len as u32);
                let ioc = at + len == end && !s.no_period_wakeup;
                self.bdl.write::<u32>(n * 16 + 12, u32::from(ioc));
                n += 1;
                at += len;
            }
        }
        if n < 2 {
            return Err(EINVAL);
        }
        let regs = &self.hda.regs;
        regs.write32(self.reg(SD_CBL), s.buffer_bytes() as u32);
        regs.write16(self.reg(SD_LVI), (n - 1) as u16);
        regs.write16(self.reg(SD_FMT), fmt);
        regs.write32(self.reg(SD_BDPL), self.bdl.phys() as u32);
        regs.write32(self.reg(SD_BDPU), (self.bdl.phys() >> 32) as u32);
        let ctl = regs.read32(self.reg(SD_CTL)) & !(0xF << 20);
        regs.write32(self.reg(SD_CTL), ctl | (u32::from(self.tag) << 20));
        regs.write8(self.reg(SD_STS), SD_STS_CLEAR);
        // The converter: the same format, our stream tag, channel 0.
        let h = &self.hda;
        h.command(verb4(self.cad, self.conv, SET_CONVERTER_FORMAT, fmt));
        h.command(verb12(self.cad, self.conv, SET_CONVERTER_STREAM, self.tag << 4));
        let ints = regs.read32(INTCTL);
        regs.write32(INTCTL, ints | INTCTL_GIE | (1 << self.index));
        self.frame_bytes.store(s.frame_bytes, Ordering::Relaxed);
        Ok(())
    }

    fn start(&self) {
        let regs = &self.hda.regs;
        let ctl = self.reg(SD_CTL);
        regs.write32(ctl, regs.read32(ctl) | SD_CTL_RUN | SD_CTL_IOCE);
    }

    fn stop(&self) {
        let regs = &self.hda.regs;
        let ctl = self.reg(SD_CTL);
        regs.write32(ctl, regs.read32(ctl) & !(SD_CTL_RUN | SD_CTL_IOCE));
        regs.write8(self.reg(SD_STS), SD_STS_CLEAR);
    }

    fn position(&self) -> u32 {
        let fb = self.frame_bytes.load(Ordering::Relaxed).max(1);
        self.hda.regs.read32(self.reg(SD_LPIB)) / fb
    }

    fn release(&self) {
        let regs = &self.hda.regs;
        regs.write32(INTCTL, regs.read32(INTCTL) & !(1 << self.index));
        // The converter leaves the stream.
        self.hda.command(verb12(self.cad, self.conv, SET_CONVERTER_STREAM, 0));
    }
}

/// An amplifier as a control: its volume (gain per channel) or its switch
/// (on = unmuted).
struct AmpCtl {
    hda: Arc<Hda>,
    cad: u8,
    nid: u8,
    output: bool,
    index: u8,
    channels: usize,
    volume: bool,
    /// Gain and mute of each channel, as last set.
    state: Arc<IrqSpinLock<[(u32, bool); 2]>>,
}

impl AmpCtl {
    fn apply(&self, st: &[(u32, bool); 2]) {
        for (ch, (gain, mute)) in st.iter().enumerate().take(self.channels) {
            let (left, right) = if self.channels == 1 { (true, true) } else { (ch == 0, ch == 1) };
            let p = amp_payload(self.output, self.index, *gain, *mute, left, right);
            self.hda.command(verb4(self.cad, self.nid, SET_AMP_GAIN_MUTE, p));
        }
    }
}

impl ElemOps for AmpCtl {
    fn get(&self, values: &mut [i64]) {
        let st = *self.state.lock();
        for (v, (gain, mute)) in values.iter_mut().zip(st.iter()) {
            *v = if self.volume { i64::from(*gain) } else { i64::from(!*mute) };
        }
    }

    fn put(&self, values: &[i64]) -> bool {
        let new = {
            let mut st = self.state.lock();
            let old = *st;
            for (v, s) in values.iter().zip(st.iter_mut()) {
                if self.volume {
                    s.0 = *v as u32;
                } else {
                    s.1 = *v == 0;
                }
            }
            if *st == old {
                return false;
            }
            *st
        };
        self.apply(&new);
        true
    }
}

/// A volume and a switch on the amplifier that sets `path`'s level.
fn amp_controls(hda: &Arc<Hda>, g: &Graph, path: &Path, playback: bool, what: &str) -> Vec<Arc<Elem>> {
    let Some((nid, output, index, caps)) = graph::volume_amp(g, path, playback) else { return Vec::new() };
    let channels = if g.widget(nid).is_some_and(|w| w.stereo()) { 2 } else { 1 };
    let zero = caps.offset().min(caps.steps());
    let state = Arc::new(IrqSpinLock::new([(zero, false); 2]));
    let make =
        |volume| AmpCtl { hda: hda.clone(), cad: g.cad, nid, output, index, channels, volume, state: state.clone() };
    let tlv = slate_alsa::tlv::db_scale(-((caps.offset() * caps.step_cdb()) as i32), caps.step_cdb(), false);
    let mut v = alloc::vec![Elem::mixer(
        &format!("{what} Volume"),
        Kind::Integer { min: 0, max: i64::from(caps.steps()), step: 1 },
        channels as u32,
        Some(tlv),
        Box::new(make(true)),
    )];
    if caps.mute() {
        v.push(Elem::mixer(&format!("{what} Switch"), Kind::Boolean, channels as u32, None, Box::new(make(false))));
    }
    v
}

/// The codec's name, as ALSA's card info shows it.
fn codec_name(vendor: u32) -> String {
    match vendor >> 16 {
        0x10ec => format!("Realtek ALC{:x}", vendor & 0xffff),
        0x1af4 => String::from("QEMU HDA"),
        0x14f1 => format!("Conexant CX{:x}", vendor & 0xffff),
        0x111d | 0x8384 => format!("IDT/Sigmatel {:04x}", vendor & 0xffff),
        0x1002 | 0x8086 | 0x10de => String::from("HDMI"),
        _ => format!("Codec {vendor:08x}"),
    }
}

/// The hardware a converter offers.
fn converter_hw(g: &Graph, nid: u8) -> Option<(Hardware, u32)> {
    let w = g.widget(nid)?;
    let (rates, bits) = graph::converter_formats(w);
    let mut formats = Vec::new();
    if bits.contains(&16) {
        formats.push(FORMAT_S16_LE);
    }
    let bits32 = if bits.contains(&32) {
        32
    } else if bits.contains(&24) {
        24
    } else {
        0
    };
    if bits32 != 0 {
        formats.push(FORMAT_S32_LE);
    }
    let rates: Vec<u32> = rates.into_iter().filter(|r| stream_format(*r, 16, 2).is_some()).collect();
    if formats.is_empty() || rates.is_empty() {
        return None;
    }
    let ch = (((w.caps >> 13) & 7) << 1) + u32::from(w.stereo()) + 1;
    Some((
        Hardware {
            info: INFO_MMAP | INFO_MMAP_VALID | INFO_INTERLEAVED | INFO_BLOCK_TRANSFER | INFO_PAUSE,
            access: Mask::of(&[ACCESS_MMAP_INTERLEAVED, ACCESS_RW_INTERLEAVED]),
            formats: Mask::of(&formats),
            msbits32: if bits32 == 24 { 24 } else { 0 },
            channels: Interval::whole(ch, ch),
            rates: Rates::of(&rates),
            period_bytes: Interval::whole(128, BUFFER_MAX / 2),
            period_align: 128,
            periods: Interval::whole(2, 32),
            buffer_bytes_max: BUFFER_MAX,
        },
        bits32,
    ))
}

/// The plan's converters as streams of the controller.
fn make_stream(
    hda: &Arc<Hda>,
    g: &Graph,
    conv: u8,
    playback: bool,
    index: usize,
) -> Option<(Arc<HdaStream>, Arc<Substream>)> {
    let (hw, bits32) = converter_hw(g, conv)?;
    let st = Arc::new(HdaStream {
        hda: hda.clone(),
        index,
        tag: if playback { 1 } else { 2 },
        cad: g.cad,
        conv,
        hw,
        bits32,
        bdl: Dma::new_below_4g(256 * 16)?,
        frame_bytes: AtomicU32::new(4),
        sub: Once::new(),
    });
    let dir = if playback { STREAM_PLAYBACK } else { STREAM_CAPTURE };
    let name = format!("{} {}", hda.name, if playback { "playback" } else { "capture" });
    let sub = Substream::new(0, dir, &name, st.clone());
    st.sub.call_once(|| Arc::downgrade(&sub));
    Some((st, sub))
}

/// Reset the controller and bring up its command rings. Returns the
/// codecs that answered (STATESTS).
fn init_controller(regs: Mmio, rings: &Rings) -> Option<u16> {
    // Reset (§4.2.2): CRST low, then high; codecs announce themselves
    // within 521 us of that.
    regs.write32(GCTL, regs.read32(GCTL) & !GCTL_CRST);
    if !spin_until(100_000_000, || regs.read32(GCTL) & GCTL_CRST == 0) {
        return None;
    }
    crate::drivers::dma::delay_ms(1);
    regs.write32(GCTL, regs.read32(GCTL) | GCTL_CRST);
    if !spin_until(100_000_000, || regs.read32(GCTL) & GCTL_CRST != 0) {
        return None;
    }
    crate::drivers::dma::delay_ms(2);
    let codecs = regs.read16(STATESTS);
    regs.write16(STATESTS, codecs);
    // The CORB (§4.4.1): stopped, 256 entries, its base, both pointers
    // reset.
    regs.write8(CORBCTL, 0);
    spin_until(10_000_000, || regs.read8(CORBCTL) & CORBCTL_RUN == 0);
    regs.write8(CORBSIZE, 2);
    regs.write32(CORBLBASE, rings.corb.phys() as u32);
    regs.write32(CORBUBASE, (rings.corb.phys() >> 32) as u32);
    regs.write16(CORBWP, 0);
    regs.write16(CORBRP, CORBRP_RST);
    spin_until(1_000_000, || regs.read16(CORBRP) & CORBRP_RST != 0);
    regs.write16(CORBRP, 0);
    spin_until(1_000_000, || regs.read16(CORBRP) & CORBRP_RST == 0);
    // The RIRB (§4.4.2): 256 entries, its write pointer reset, DMA on, no
    // interrupts (responses are polled).
    regs.write8(RIRBCTL, 0);
    regs.write8(RIRBSIZE, 2);
    regs.write32(RIRBLBASE, rings.rirb.phys() as u32);
    regs.write32(RIRBUBASE, (rings.rirb.phys() >> 32) as u32);
    regs.write16(RIRBWP, RIRBWP_RST);
    regs.write16(RINTCNT, 0xff);
    regs.write8(RIRBCTL, RIRBCTL_DMAEN);
    regs.write8(CORBCTL, CORBCTL_RUN);
    // No DMA position buffer: positions come from each stream's LPIB.
    regs.write32(DPLBASE, 0);
    regs.write32(DPUBASE, 0);
    Some(codecs)
}

pub fn probe(pci: Arc<Device>) -> Option<()> {
    pci.enable();
    let Some(base) = pci.map_bar(0) else {
        log_warn!("hda {:?}: no memory BAR", pci.address);
        return None;
    };
    let regs = Mmio(base);
    let gcap = regs.read16(GCAP);
    let (oss, iss) = (usize::from((gcap >> 12) & 0xf), usize::from((gcap >> 8) & 0xf));
    if gcap & 1 == 0 {
        // Buffers are user pages anywhere in memory.
        log_warn!("hda {:?}: the controller addresses only 32 bits; not used (GAPS.md)", pci.address);
        return None;
    }
    let rings = Rings { corb: Dma::new_below_4g(1024)?, rirb: Dma::new_below_4g(2048)?, corb_wp: 0, rirb_rp: 0 };
    let Some(codecs) = init_controller(regs, &rings) else {
        log_warn!("hda {:?}: did not come out of reset", pci.address);
        return None;
    };
    let rings = Rings { rirb_rp: regs.read16(RIRBWP) & 0xff, ..rings };
    let name = format!("hda {}", crate::drivers::pci_sys::name(pci.address));
    let hda = Arc::new(Hda { name, regs, rings: IrqSpinLock::new(rings), streams: IrqSpinLock::new(Vec::new()) });
    let slot: Arc<Once<Arc<Hda>>> = Arc::new(Once::new());
    let irq_slot = slot.clone();
    let handler = move || {
        if let Some(h) = irq_slot.get() {
            h.interrupt();
        }
    };
    slot.call_once(|| hda.clone());
    let how = pci
        .enable_interrupt("hda", Box::new(handler.clone()))
        .map(String::from)
        .or_else(|| pci.enable_intx("hda", Box::new(handler)).map(|g| format!("INTx on GSI {g}")))
        .unwrap_or_else(|| String::from("polled"));

    // The first codec with an analog path.
    let mut chosen: Option<(Graph, Plan)> = None;
    for cad in (0..15u8).filter(|c| codecs & (1 << c) != 0) {
        let Some(g) = graph::read(&mut Link(&hda), cad) else { continue };
        let plan = graph::plan(&g);
        log_info!(
            "hda {:?}: codec {cad}: {:08x} ({}), {} widgets, {} outputs, input {}",
            pci.address,
            g.vendor,
            codec_name(g.vendor),
            g.widgets.len(),
            plan.outputs.len(),
            plan.input.as_ref().map_or(String::from("none"), |p| format!("{:?}", p.0))
        );
        if chosen.is_none() && (plan.dac.is_some() || plan.adc.is_some()) {
            chosen = Some((g, plan));
        }
    }
    let Some((g, plan)) = chosen else {
        log_info!("hda {:?}: no codec with analog outputs or inputs (digital audio: GAPS.md)", pci.address);
        return Some(());
    };
    for v in graph::setup_verbs(&g, &plan) {
        hda.command(v);
    }

    let mut controls = Vec::new();
    let mut pcm = super::Pcm {
        device: 0,
        id: format!("{} Analog", codec_name(g.vendor)),
        name: format!("{} Analog", codec_name(g.vendor)),
        playback: None,
        capture: None,
    };
    if let (Some(dac), true) = (plan.dac, oss > 0)
        && let Some((st, sub)) = make_stream(&hda, &g, dac, true, iss)
    {
        hda.streams.lock().push(st);
        pcm.playback = Some(sub);
        controls.extend(amp_controls(&hda, &g, &plan.outputs[0].1, true, "Master Playback"));
    }
    if let (Some(adc), Some(path), true) = (plan.adc, plan.input.as_ref(), iss > 0)
        && let Some((st, sub)) = make_stream(&hda, &g, adc, false, 0)
    {
        hda.streams.lock().push(st);
        pcm.capture = Some(sub);
        controls.extend(amp_controls(&hda, &g, path, false, "Capture"));
    }
    if pcm.playback.is_none() && pcm.capture.is_none() {
        log_warn!("hda {:?}: the codec's converters take no format Slate plays", pci.address);
        return Some(());
    }
    let intel = pci.vendor == 0x8086;
    let addr = match pci.bars[0] {
        Some(crate::drivers::pci::Bar::Memory { address, .. }) => address,
        _ => 0,
    };
    let card_name = if intel { "HDA Intel" } else { "HD-Audio Generic" };
    let card = super::register(super::NewCard {
        id: String::from(if intel { "Intel" } else { "Generic" }),
        driver: String::from("HDA-Intel"),
        name: String::from(card_name),
        longname: format!("{card_name} at {addr:#x}"),
        mixername: codec_name(g.vendor),
        components: format!("HDA:{:08x}", g.vendor),
        parent: crate::drivers::pci_sys::path(pci.address),
        pcms: alloc::vec![pcm],
        controls,
    });
    log_info!(
        "hda {:?}: {} input and {} output streams, {how}{}",
        pci.address,
        iss,
        oss,
        if card.is_some() { "" } else { "; no card number left" }
    );
    Some(())
}
