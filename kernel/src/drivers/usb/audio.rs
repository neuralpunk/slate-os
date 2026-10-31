// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB audio (ADR 0184): USB Audio Class 1.0 devices' playback, as a
//! sound card (`slate_usb::audio` reads their descriptors).
//!
//! The streaming interface's alternate setting and its sampling frequency
//! are set when a program sets its hardware parameters. Playing keeps a
//! few milliseconds of isochronous packets queued, one per service
//! interval, each the frames due by its end (44.1 kHz at 1000 packets a
//! second: 44 or 45 frames), copied from the program's buffer into the
//! driver's own; each completion queues the next and moves the position.
//! The feature unit on the playback path gives `PCM Playback Volume` and
//! `Switch`. Recording, Audio Class 2.0 devices and asynchronous
//! endpoints' feedback are left for later (GAPS.md).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use slate_alsa::abi::*;
use slate_alsa::params::{Hardware, Interval, Mask, Setup, alloc_free::Rates};
use slate_sync::Once;
use slate_usb::audio::{self as uac, Alt};

use super::xhci::{Endpoint, UsbDevice};
use super::{EP_ISOCH, EndpointDesc};
use crate::abi::linux::errno::*;
use crate::drivers::dma::Dma;
use crate::drivers::sound::control::{Elem, ElemOps, Kind};
use crate::drivers::sound::pcm::{Pages, PcmOps, Substream};
use crate::fs::vfs::Result;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// Packets kept queued (milliseconds at full speed).
const QUEUED: u32 = 8;
/// Bounce slots: more than are ever queued.
const SLOTS: usize = 32;
/// SET_INTERFACE (USB 2.0 §9.4.10), to an interface.
const REQ_SET_INTERFACE: u8 = 0x0B;
const RT_INTERFACE_OUT: u8 = 0x01;

struct Play {
    running: bool,
    buf: Option<Arc<Pages>>,
    frame_bytes: u32,
    buffer_size: u32,
    period_size: u32,
    rate: u32,
    /// Frames taken from the buffer (its offset), packets sent, frames
    /// since the last period, packets in flight.
    pos: u32,
    seq: u64,
    since_period: u32,
    inflight: u32,
}

pub struct UsbStream {
    dev: Arc<UsbDevice>,
    ep: Arc<Endpoint>,
    alt: Alt,
    interface: u8,
    /// Packets a second (1000 at full speed, more for high speed).
    per_second: u32,
    bounce: Dma,
    slot_bytes: usize,
    hw: Hardware,
    play: IrqSpinLock<Play>,
    sub: Once<Weak<Substream>>,
}

impl UsbStream {
    /// Queue the next packet (with the lock held); false if it can't.
    fn queue_one(&self, p: &mut Play) -> bool {
        let Some(buf) = p.buf.clone() else { return false };
        let n = uac::packet_frames(p.rate, self.per_second, p.seq);
        let bytes = (n * p.frame_bytes) as usize;
        if bytes > self.slot_bytes || bytes > 1024 || n > p.buffer_size {
            return false;
        }
        let slot = (p.seq % SLOTS as u64) as usize;
        let mut chunk = [0u8; 1024];
        let chunk = &mut chunk[..bytes.min(1024)];
        // The frames from the buffer's position, wrapping at its end.
        let fb = p.frame_bytes as usize;
        let first = n.min(p.buffer_size - p.pos) as usize;
        buf.read(p.pos as usize * fb, &mut chunk[..first * fb]);
        if first < n as usize {
            buf.read(0, &mut chunk[first * fb..]);
        }
        self.bounce.copy_in(slot * self.slot_bytes, chunk);
        self.dev.queue_isoch(&self.ep, self.bounce.phys() + (slot * self.slot_bytes) as u64, bytes);
        p.pos = (p.pos + n) % p.buffer_size;
        p.seq += 1;
        p.since_period += n;
        p.inflight += 1;
        true
    }

    /// A packet went (from the controller's events).
    fn completed(&self) {
        let elapsed = {
            let mut p = self.play.lock();
            p.inflight = p.inflight.saturating_sub(1);
            if !p.running {
                return;
            }
            while p.inflight < QUEUED && self.queue_one(&mut p) {}
            let e = p.since_period >= p.period_size;
            if e {
                p.since_period %= p.period_size.max(1);
            }
            e
        };
        if elapsed && let Some(s) = self.sub.get().and_then(Weak::upgrade) {
            s.period_elapsed();
        }
    }
}

impl PcmOps for UsbStream {
    fn hardware(&self) -> Hardware {
        self.hw.clone()
    }

    /// The alternate setting and the rate (control transfers: from the
    /// program's hw_params, never under the stream's lock).
    fn configure(&self, s: &Setup) -> Result<()> {
        let d = &self.dev;
        d.control(RT_INTERFACE_OUT, REQ_SET_INTERFACE, u16::from(self.alt.alt), u16::from(self.interface), &mut [])
            .map_err(|_| EIO)?;
        if self.alt.freq_control {
            let mut rate = [s.rate as u8, (s.rate >> 8) as u8, (s.rate >> 16) as u8];
            let value = u16::from(uac::EP_SAMPLING_FREQ) << 8;
            if d.control(uac::RT_CLASS_ENDPOINT_OUT, uac::SET_CUR, value, u16::from(self.alt.endpoint), &mut rate)
                .is_err()
            {
                log_warn!("USB port {}: the device refused {} Hz", d.port, s.rate);
            }
        }
        Ok(())
    }

    fn prepare(&self, s: &Setup, buf: &Arc<Pages>) -> Result<()> {
        let mut p = self.play.lock();
        p.running = false;
        p.buf = Some(buf.clone());
        p.frame_bytes = s.frame_bytes;
        p.buffer_size = s.buffer_size;
        p.period_size = s.period_size;
        p.rate = s.rate;
        p.pos = 0;
        p.seq = 0;
        p.since_period = 0;
        Ok(())
    }

    fn start(&self) {
        let mut p = self.play.lock();
        p.running = true;
        while p.inflight < QUEUED && self.queue_one(&mut p) {}
    }

    fn stop(&self) {
        self.play.lock().running = false;
    }

    fn position(&self) -> u32 {
        self.play.lock().pos
    }

    fn release(&self) {
        let mut p = self.play.lock();
        p.running = false;
        p.buf = None;
    }
}

/// A feature unit control: volume (in the device's steps from its
/// minimum) or the switch (on = not muted), on the master channel or each
/// channel.
struct FuCtl {
    dev: Arc<UsbDevice>,
    unit: u8,
    interface: u8,
    channels: Vec<u8>,
    volume: bool,
    min: i16,
    res: i16,
}

impl FuCtl {
    fn index(&self) -> u16 {
        (u16::from(self.unit) << 8) | u16::from(self.interface)
    }
}

impl ElemOps for FuCtl {
    fn get(&self, values: &mut [i64]) {
        for (v, &ch) in values.iter_mut().zip(&self.channels) {
            let cs = if self.volume { uac::FU_VOLUME } else { uac::FU_MUTE };
            let mut b = [0u8; 2];
            let len = if self.volume { 2 } else { 1 };
            let value = (u16::from(cs) << 8) | u16::from(ch);
            if self.dev.control(uac::RT_CLASS_INTERFACE_IN, uac::GET_CUR, value, self.index(), &mut b[..len]).is_ok() {
                *v = if self.volume {
                    i64::from(i16::from_le_bytes(b).saturating_sub(self.min)) / i64::from(self.res.max(1))
                } else {
                    i64::from(b[0] == 0)
                };
            }
        }
    }

    fn put(&self, values: &[i64]) -> bool {
        let mut old = alloc::vec![0i64; values.len()];
        self.get(&mut old);
        if old == values {
            return false;
        }
        for (v, &ch) in values.iter().zip(&self.channels) {
            let (cs, mut data): (u8, Vec<u8>) = if self.volume {
                let raw = (i64::from(self.min) + v * i64::from(self.res.max(1))) as i16;
                (uac::FU_VOLUME, raw.to_le_bytes().to_vec())
            } else {
                (uac::FU_MUTE, alloc::vec![u8::from(*v == 0)])
            };
            let value = (u16::from(cs) << 8) | u16::from(ch);
            let _ = self.dev.control(uac::RT_CLASS_INTERFACE_OUT, uac::SET_CUR, value, self.index(), &mut data);
        }
        true
    }
}

/// Read a 16-bit volume attribute (GET_MIN, GET_MAX, GET_RES).
fn volume_attr(dev: &UsbDevice, req: u8, unit: u8, interface: u8, ch: u8) -> Option<i16> {
    let mut b = [0u8; 2];
    let value = (u16::from(uac::FU_VOLUME) << 8) | u16::from(ch);
    dev.control(uac::RT_CLASS_INTERFACE_IN, req, value, (u16::from(unit) << 8) | u16::from(interface), &mut b).ok()?;
    Some(i16::from_le_bytes(b))
}

fn controls(dev: &Arc<UsbDevice>, f: &uac::Function, alt: &Alt) -> Vec<Arc<Elem>> {
    let mut out = Vec::new();
    let Some(fu) = f.feature_for(alt) else { return out };
    let iface = f.control;
    // The master channel's controls, else each channel's.
    let pick = |bit| -> Vec<u8> {
        if fu.has(0, bit) {
            alloc::vec![0]
        } else {
            (1..=alt.channels).filter(|&c| fu.has(usize::from(c), bit)).collect()
        }
    };
    let vol = pick(1);
    if let Some(&ch) = vol.first()
        && let (Some(min), Some(max), Some(res)) = (
            volume_attr(dev, uac::GET_MIN, fu.id, iface, ch),
            volume_attr(dev, uac::GET_MAX, fu.id, iface, ch),
            volume_attr(dev, uac::GET_RES, fu.id, iface, ch),
        )
        && max > min
    {
        let res = res.max(1);
        let steps = (i32::from(max) - i32::from(min)) / i32::from(res);
        // 1/256 dB units, as hundredths of a dB.
        let tlv = slate_alsa::tlv::db_scale(i32::from(min) * 100 / 256, (i32::from(res) * 100 / 256) as u32, false);
        out.push(Elem::mixer(
            "PCM Playback Volume",
            Kind::Integer { min: 0, max: i64::from(steps), step: 1 },
            vol.len() as u32,
            Some(tlv),
            Box::new(FuCtl { dev: dev.clone(), unit: fu.id, interface: iface, channels: vol, volume: true, min, res }),
        ));
    }
    let mute = pick(0);
    if !mute.is_empty() {
        out.push(Elem::mixer(
            "PCM Playback Switch",
            Kind::Boolean,
            mute.len() as u32,
            None,
            Box::new(FuCtl {
                dev: dev.clone(),
                unit: fu.id,
                interface: iface,
                channels: mute,
                volume: false,
                min: 0,
                res: 1,
            }),
        ));
    }
    out
}

/// The formats a stream's samples are in.
fn format_of(alt: &Alt) -> Option<u32> {
    match alt.subframe {
        2 => Some(FORMAT_S16_LE),
        3 => Some(FORMAT_S24_3LE),
        4 => Some(FORMAT_S32_LE),
        _ => None,
    }
}

/// Cards of USB devices, to unplug.
static CARDS: IrqSpinLock<Vec<(Weak<UsbDevice>, Arc<crate::drivers::sound::Card>)>> = IrqSpinLock::new(Vec::new());

/// The device's audio function, if it has one Slate plays through: its
/// card. Returns whether it took the device's audio interfaces.
/// What the device calls itself, and where it is in /sys.
pub struct Names<'a> {
    pub maker: Option<&'a str>,
    pub product: Option<&'a str>,
    /// The device's directory and name in /sys ("devices/.../usb1/1-3",
    /// "1-3").
    pub sys_path: &'a str,
    pub sys_name: &'a str,
}

pub fn start(dev: &Arc<UsbDevice>, config: &slate_usb::Configuration, names: &Names) -> bool {
    let Some(f) = uac::parse(&config.raw) else { return false };
    // Playback: the alternate setting with the most usual format (16-bit
    // stereo first).
    let mut alts: Vec<(&uac::Streaming, &Alt)> = f
        .streams
        .iter()
        .flat_map(|s| s.alts.iter().map(move |a| (s, a)))
        .filter(|(_, a)| !a.is_in() && format_of(a).is_some() && (1..=8).contains(&a.channels))
        .collect();
    alts.sort_by_key(|(_, a)| (a.subframe != 2, a.channels != 2, a.alt));
    let Some(&(streaming, alt)) = alts.first() else {
        log_info!("USB port {}: an audio device with no playback Slate takes (recording: GAPS.md)", dev.port);
        return false;
    };
    let fb = u32::from(alt.subframe) * u32::from(alt.channels);
    // Packets a second: full speed one a frame (1 ms); high speed 8000
    // over 2^(bInterval - 1).
    let per_second =
        if dev.speed >= super::xhci::SPEED_HIGH { 8000 >> u32::from(alt.interval.clamp(1, 4) - 1) } else { 1000 };
    let rates: Vec<u32> = alt
        .rates
        .common()
        .into_iter()
        .filter(|r| (r.div_ceil(per_second) * fb) as usize <= usize::from(alt.max_packet))
        .collect();
    let Some(format) = format_of(alt) else { return false };
    if rates.is_empty() {
        log_warn!("USB port {}: no rate fits the audio endpoint's packets", dev.port);
        return false;
    }
    if alt.sync() == 1 {
        log_info!("USB port {}: asynchronous audio endpoint: played at the nominal rate (GAPS.md)", dev.port);
    }
    let desc = EndpointDesc {
        address: alt.endpoint,
        kind: EP_ISOCH,
        max_packet: alt.max_packet,
        interval: alt.interval,
        max_streams: 0,
    };
    let Some(ep) = dev.configure(&[desc]).and_then(|v| v.into_iter().next()) else {
        log_warn!("USB port {}: the audio endpoint could not be configured", dev.port);
        return false;
    };
    let slot_bytes = usize::from(alt.max_packet).next_multiple_of(64);
    let Some(bounce) = Dma::new(SLOTS * slot_bytes) else { return false };
    let hw = Hardware {
        info: INFO_MMAP | INFO_MMAP_VALID | INFO_INTERLEAVED | INFO_BLOCK_TRANSFER | INFO_PAUSE | INFO_BATCH,
        access: Mask::of(&[ACCESS_MMAP_INTERLEAVED, ACCESS_RW_INTERLEAVED]),
        formats: Mask::of(&[format]),
        msbits32: if format == FORMAT_S32_LE { u32::from(alt.bits) } else { 0 },
        channels: Interval::whole(u32::from(alt.channels), u32::from(alt.channels)),
        rates: Rates::of(&rates),
        period_bytes: Interval::whole(fb * 32, 128 * 1024),
        period_align: fb,
        periods: Interval::whole(2, 64),
        buffer_bytes_max: 256 * 1024,
    };
    let st = Arc::new(UsbStream {
        dev: dev.clone(),
        ep: ep.clone(),
        alt: alt.clone(),
        interface: streaming.interface,
        per_second,
        bounce,
        slot_bytes,
        hw,
        play: IrqSpinLock::new(Play {
            running: false,
            buf: None,
            frame_bytes: fb,
            buffer_size: 1,
            period_size: 1,
            rate: rates[0],
            pos: 0,
            seq: 0,
            since_period: 0,
            inflight: 0,
        }),
        sub: Once::new(),
    });
    let handler_st = Arc::downgrade(&st);
    dev.hc.set_pipe(
        dev.slot,
        ep.dci,
        Box::new(move |_code, _residual| {
            if let Some(s) = handler_st.upgrade() {
                s.completed();
            }
        }),
    );
    let product = String::from(names.product.unwrap_or("USB Audio"));
    let maker = names.maker.unwrap_or("");
    let sub = Substream::new(0, STREAM_PLAYBACK, &format!("usb-audio {}", dev.port), st.clone());
    st.sub.call_once(|| Arc::downgrade(&sub));
    let short = product.rsplit(' ').next().unwrap_or("Audio");
    let speed = if dev.speed >= super::xhci::SPEED_HIGH { "high speed" } else { "full speed" };
    let card = crate::drivers::sound::register(crate::drivers::sound::NewCard {
        id: String::from(short),
        driver: String::from("USB-Audio"),
        name: product.clone(),
        longname: format!("{} {} at usb-{}, {speed}", maker, product, dev.port).trim().into(),
        mixername: String::from("USB Mixer"),
        components: String::from("USB"),
        parent: format!("{}/{}:{}.{}", names.sys_path, names.sys_name, config.value, f.control),
        pcms: alloc::vec![crate::drivers::sound::Pcm {
            device: 0,
            id: String::from("USB Audio"),
            name: String::from("USB Audio"),
            playback: Some(sub),
            capture: None,
        }],
        controls: controls(dev, &f, alt),
    });
    let Some(card) = card else { return false };
    CARDS.lock().push((Arc::downgrade(dev), card));
    log_info!(
        "USB port {}: audio: {} channels, {} bits, {:?} Hz, endpoint {:#04x} ({} bytes)",
        dev.port,
        alt.channels,
        alt.bits,
        rates,
        alt.endpoint,
        alt.max_packet
    );
    true
}

/// The device was unplugged: its card goes.
pub fn detached(dev: &Arc<UsbDevice>) {
    let gone: Vec<Arc<crate::drivers::sound::Card>> = {
        let mut cards = CARDS.lock();
        let (gone, keep): (Vec<_>, Vec<_>) =
            cards.drain(..).partition(|(d, _)| d.upgrade().is_none_or(|d| Arc::ptr_eq(&d, dev)));
        *cards = keep;
        gone.into_iter().map(|(_, c)| c).collect()
    };
    for c in gone {
        crate::drivers::sound::unregister(&c);
    }
}
