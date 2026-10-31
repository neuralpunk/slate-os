// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB Audio Class 1.0 functions (ADR 0184). Source: usb.org's *Device
//! Class Definition for Audio Devices* 1.0 (1998): §4.3.2 the
//! AudioControl interface's class-specific descriptors (header 01h, input
//! terminal 02h, output terminal 03h, feature unit 06h), §4.5.2 the
//! AudioStreaming interface's (general 01h, format type 02h), §4.6.1.2 the
//! class-specific isochronous endpoint (general 01h: bit 0, the sampling
//! frequency control); §5.2.2 the requests (SET_CUR 01h, GET_CUR 81h,
//! GET_MIN 82h, GET_MAX 83h, GET_RES 84h; feature unit controls mute 01h
//! and volume 02h; the endpoint's sampling frequency control 01h); and
//! *Audio Data Formats* 1.0 §2.2.5 (the type I format descriptor: channels,
//! subframe size, bit resolution, and either a continuous range or a list
//! of 3-byte sampling frequencies). Terminal types are from *Audio
//! Terminal Types* 1.0 (0101h USB streaming).

use alloc::vec::Vec;

use crate::{DESC_CS_INTERFACE, DESC_ENDPOINT, DESC_INTERFACE};

/// The audio interface class and its subclasses.
pub const CLASS_AUDIO: u8 = 1;
pub const SUBCLASS_CONTROL: u8 = 1;
pub const SUBCLASS_STREAMING: u8 = 2;
/// A class-specific endpoint descriptor.
pub const DESC_CS_ENDPOINT: u8 = 0x25;

// AudioControl descriptor subtypes.
const AC_HEADER: u8 = 0x01;
const AC_INPUT_TERMINAL: u8 = 0x02;
const AC_OUTPUT_TERMINAL: u8 = 0x03;
const AC_FEATURE_UNIT: u8 = 0x06;
// AudioStreaming descriptor subtypes.
const AS_GENERAL: u8 = 0x01;
const AS_FORMAT_TYPE: u8 = 0x02;
/// The PCM format tag, and format type I.
pub const FORMAT_PCM: u16 = 0x0001;
const FORMAT_TYPE_I: u8 = 0x01;
/// The USB streaming terminal type.
pub const TERMINAL_STREAMING: u16 = 0x0101;

// Requests and controls (§5.2.2, Appendix A.9, A.10.2).
pub const SET_CUR: u8 = 0x01;
pub const GET_CUR: u8 = 0x81;
pub const GET_MIN: u8 = 0x82;
pub const GET_MAX: u8 = 0x83;
pub const GET_RES: u8 = 0x84;
pub const FU_MUTE: u8 = 0x01;
pub const FU_VOLUME: u8 = 0x02;
pub const EP_SAMPLING_FREQ: u8 = 0x01;
/// bmRequestType for class requests to an interface or an endpoint.
pub const RT_CLASS_INTERFACE_IN: u8 = 0xA1;
pub const RT_CLASS_INTERFACE_OUT: u8 = 0x21;
pub const RT_CLASS_ENDPOINT_OUT: u8 = 0x22;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub id: u8,
    pub kind: u16,
    pub input: bool,
    /// An output terminal's source.
    pub source: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feature {
    pub id: u8,
    pub source: u8,
    /// Controls of the master channel (0), then each channel.
    pub controls: Vec<u32>,
}

impl Feature {
    /// Whether channel `ch` (0: master) has control `bit` (mute 0,
    /// volume 1).
    pub fn has(&self, ch: usize, bit: u32) -> bool {
        self.controls.get(ch).is_some_and(|c| c >> bit & 1 == 1)
    }
}

/// The sampling frequencies an alternate setting takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rates {
    List(Vec<u32>),
    Range(u32, u32),
}

impl Rates {
    /// The usual rates it takes, ascending.
    pub fn common(&self) -> Vec<u32> {
        const COMMON: [u32; 8] = [8000, 16000, 22050, 32000, 44100, 48000, 88200, 96000];
        match self {
            Rates::List(l) => {
                let mut v = l.clone();
                v.sort_unstable();
                v.dedup();
                v
            }
            Rates::Range(lo, hi) => COMMON.iter().copied().filter(|r| r >= lo && r <= hi).collect(),
        }
    }
}

/// An alternate setting of an AudioStreaming interface that carries PCM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alt {
    pub alt: u8,
    pub terminal: u8,
    pub channels: u8,
    /// Bytes per sample in a frame, and the bits that carry it.
    pub subframe: u8,
    pub bits: u8,
    pub rates: Rates,
    pub endpoint: u8,
    /// bmAttributes: the transfer type (1, isochronous) and the
    /// synchronization type in bits 3:2 (1 asynchronous, 2 adaptive, 3
    /// synchronous).
    pub ep_attributes: u8,
    pub max_packet: u16,
    pub interval: u8,
    /// The endpoint's sampling frequency can be set.
    pub freq_control: bool,
}

impl Alt {
    pub fn is_in(&self) -> bool {
        self.endpoint & 0x80 != 0
    }
    pub fn sync(&self) -> u8 {
        (self.ep_attributes >> 2) & 3
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Streaming {
    pub interface: u8,
    pub alts: Vec<Alt>,
}

/// An audio function: its control interface, units and terminals, and its
/// streaming interfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    pub control: u8,
    pub terminals: Vec<Terminal>,
    pub features: Vec<Feature>,
    pub streams: Vec<Streaming>,
}

impl Function {
    /// The feature unit on a stream's path: for playback the one fed from
    /// the streaming input terminal (directly or through another unit),
    /// for recording the one feeding the streaming output terminal.
    pub fn feature_for(&self, alt: &Alt) -> Option<&Feature> {
        if alt.is_in() {
            let ot = self.terminals.iter().find(|t| t.id == alt.terminal && !t.input)?;
            let mut at = ot.source;
            for _ in 0..4 {
                if let Some(f) = self.features.iter().find(|f| f.id == at) {
                    return Some(f);
                }
                at = self.features.iter().find(|f| f.id == at)?.source;
            }
            None
        } else {
            let mut from = alt.terminal;
            for _ in 0..4 {
                let f = self.features.iter().find(|f| f.source == from)?;
                if f.controls.iter().any(|c| c & 3 != 0) {
                    return Some(f);
                }
                from = f.id;
            }
            None
        }
    }
}

fn u16_at(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([d.get(i).copied().unwrap_or(0), d.get(i + 1).copied().unwrap_or(0)])
}

fn u24_at(d: &[u8], i: usize) -> u32 {
    u32::from(d.get(i).copied().unwrap_or(0))
        | u32::from(d.get(i + 1).copied().unwrap_or(0)) << 8
        | u32::from(d.get(i + 2).copied().unwrap_or(0)) << 16
}

/// The audio function in a configuration's descriptors (`raw`), if there
/// is one.
pub fn parse(raw: &[u8]) -> Option<Function> {
    let mut f = Function::default();
    let mut found = false;
    // The interface descriptor in force: (number, alt, subclass).
    let mut cur: Option<(u8, u8, u8)> = None;
    // An alternate setting being read.
    let mut alt: Option<Alt> = None;
    let finish = |f: &mut Function, alt: &mut Option<Alt>, number: u8| {
        if let Some(a) = alt.take()
            && a.endpoint != 0
        {
            match f.streams.iter_mut().find(|s| s.interface == number) {
                Some(s) => s.alts.push(a),
                None => f.streams.push(Streaming { interface: number, alts: alloc::vec![a] }),
            }
        }
    };
    let mut i = 0;
    while i + 2 <= raw.len() {
        let len = usize::from(raw[i]);
        if len < 2 || i + len > raw.len() {
            break;
        }
        let d = &raw[i..i + len];
        match d[1] {
            DESC_INTERFACE if len >= 9 => {
                if let Some((n, ..)) = cur {
                    finish(&mut f, &mut alt, n);
                }
                cur = (d[5] == CLASS_AUDIO).then_some((d[2], d[3], d[6]));
                if let Some((n, a, SUBCLASS_CONTROL)) = cur
                    && a == 0
                    && !found
                {
                    f.control = n;
                    found = true;
                }
                if let Some((_, a, SUBCLASS_STREAMING)) = cur
                    && a != 0
                {
                    alt = Some(Alt {
                        alt: a,
                        terminal: 0,
                        channels: 0,
                        subframe: 0,
                        bits: 0,
                        rates: Rates::List(Vec::new()),
                        endpoint: 0,
                        ep_attributes: 0,
                        max_packet: 0,
                        interval: 0,
                        freq_control: false,
                    });
                }
            }
            DESC_CS_INTERFACE if len >= 3 => match cur {
                Some((_, _, SUBCLASS_CONTROL)) => match d[2] {
                    AC_INPUT_TERMINAL if len >= 12 => {
                        f.terminals.push(Terminal { id: d[3], kind: u16_at(d, 4), input: true, source: 0 })
                    }
                    AC_OUTPUT_TERMINAL if len >= 9 => {
                        f.terminals.push(Terminal { id: d[3], kind: u16_at(d, 4), input: false, source: d[7] })
                    }
                    AC_FEATURE_UNIT if len >= 7 => {
                        let size = usize::from(d[5]).max(1);
                        let n = (len - 7) / size;
                        let controls = (0..n)
                            .map(|c| (0..size).fold(0u32, |v, k| v | u32::from(d[6 + c * size + k]) << (8 * k)))
                            .collect();
                        f.features.push(Feature { id: d[3], source: d[4], controls });
                    }
                    AC_HEADER => {}
                    _ => {}
                },
                Some((_, _, SUBCLASS_STREAMING)) => {
                    if let Some(a) = alt.as_mut() {
                        match d[2] {
                            AS_GENERAL if len >= 7 => {
                                a.terminal = d[3];
                                if u16_at(d, 5) != FORMAT_PCM {
                                    alt = None;
                                }
                            }
                            AS_FORMAT_TYPE if len >= 8 && d[3] == FORMAT_TYPE_I => {
                                a.channels = d[4];
                                a.subframe = d[5];
                                a.bits = d[6];
                                let n = usize::from(d[7]);
                                a.rates = if n == 0 && len >= 14 {
                                    Rates::Range(u24_at(d, 8), u24_at(d, 11))
                                } else {
                                    Rates::List(
                                        (0..n).filter(|k| 8 + 3 * k + 3 <= len).map(|k| u24_at(d, 8 + 3 * k)).collect(),
                                    )
                                };
                            }
                            AS_FORMAT_TYPE => alt = None,
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            DESC_ENDPOINT if len >= 7 => {
                if let Some(a) = alt.as_mut()
                    && d[3] & 3 == 1
                    && a.endpoint == 0
                {
                    a.endpoint = d[2];
                    a.ep_attributes = d[3];
                    a.max_packet = u16_at(d, 4) & 0x7FF;
                    a.interval = d[6];
                }
            }
            DESC_CS_ENDPOINT if len >= 3 => {
                if let Some(a) = alt.as_mut()
                    && d[2] == AS_GENERAL
                {
                    a.freq_control = d.get(3).is_some_and(|b| b & 1 != 0);
                }
            }
            _ => {}
        }
        i += len;
    }
    if let Some((n, ..)) = cur {
        finish(&mut f, &mut alt, n);
    }
    found.then_some(f)
}

/// Bytes of the next isochronous packet at `rate` frames a second of
/// `frame` bytes, one packet every `per_second`-th of a second: the
/// whole frames due by the end of packet `n` less those already sent
/// (44.1 kHz at 1000 packets a second: 44, ..., 45).
pub fn packet_frames(rate: u32, per_second: u32, n: u64) -> u32 {
    let due = |k: u64| k * u64::from(rate) / u64::from(per_second);
    (due(n + 1) - due(n)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A headset: playback (USB streaming IT 1 -> FU 2 -> speaker OT 3)
    /// and a microphone (mic IT 4 -> FU 5 -> streaming OT 6); its playback
    /// interface takes 48 and 44.1 kHz, 16-bit stereo; its recording one a
    /// range, mono.
    fn headset() -> Vec<u8> {
        let mut d: Vec<u8> = Vec::new();
        d.extend_from_slice(&[9, 2, 0, 0, 3, 1, 0, 0x80, 50]);
        // AudioControl.
        d.extend_from_slice(&[9, 4, 0, 0, 0, 1, 1, 0, 0]);
        d.extend_from_slice(&[10, 0x24, 1, 0, 1, 64, 0, 2, 1, 2]);
        d.extend_from_slice(&[12, 0x24, 2, 1, 0x01, 0x01, 0, 2, 3, 0, 0, 0]);
        d.extend_from_slice(&[10, 0x24, 6, 2, 1, 1, 0x03, 0x00, 0x00, 0]);
        d.extend_from_slice(&[9, 0x24, 3, 3, 0x01, 0x03, 0, 2, 0]);
        d.extend_from_slice(&[12, 0x24, 2, 4, 0x01, 0x02, 0, 1, 0, 0, 0, 0]);
        d.extend_from_slice(&[8, 0x24, 6, 5, 4, 1, 0x03, 0]);
        d.extend_from_slice(&[9, 0x24, 3, 6, 0x01, 0x01, 0, 5, 0]);
        // Playback streaming: alt 0, then alt 1.
        d.extend_from_slice(&[9, 4, 1, 0, 0, 1, 2, 0, 0]);
        d.extend_from_slice(&[9, 4, 1, 1, 1, 1, 2, 0, 0]);
        d.extend_from_slice(&[7, 0x24, 1, 1, 1, 0x01, 0x00]);
        d.extend_from_slice(&[14, 0x24, 2, 1, 2, 2, 16, 2, 0x80, 0xBB, 0x00, 0x44, 0xAC, 0x00]);
        d.extend_from_slice(&[9, 5, 0x01, 0x09, 192, 0, 1, 0, 0]);
        d.extend_from_slice(&[7, 0x25, 1, 1, 0, 0, 0]);
        // Recording streaming.
        d.extend_from_slice(&[9, 4, 2, 0, 0, 1, 2, 0, 0]);
        d.extend_from_slice(&[9, 4, 2, 1, 1, 1, 2, 0, 0]);
        d.extend_from_slice(&[7, 0x24, 1, 6, 1, 0x01, 0x00]);
        d.extend_from_slice(&[14, 0x24, 2, 1, 1, 2, 16, 0, 0x40, 0x1F, 0x00, 0x80, 0xBB, 0x00]);
        d.extend_from_slice(&[9, 5, 0x82, 0x05, 96, 0, 1, 0, 0]);
        d.extend_from_slice(&[7, 0x25, 1, 0, 0, 0, 0]);
        let total = d.len() as u16;
        d[2..4].copy_from_slice(&total.to_le_bytes());
        d
    }

    #[test]
    fn a_headset() {
        let f = parse(&headset()).unwrap();
        assert_eq!(f.control, 0);
        assert_eq!(f.terminals.len(), 4);
        assert_eq!(f.features.len(), 2);
        assert_eq!(f.streams.len(), 2);
        let play = &f.streams[0].alts[0];
        assert_eq!((play.alt, play.terminal, play.channels, play.subframe, play.bits), (1, 1, 2, 2, 16));
        assert_eq!(play.rates.common(), alloc::vec![44100, 48000]);
        assert_eq!((play.endpoint, play.sync(), play.max_packet, play.freq_control), (0x01, 2, 192, true));
        assert!(!play.is_in());
        let fu = f.feature_for(play).unwrap();
        assert_eq!(fu.id, 2);
        assert!(fu.has(0, 0) && fu.has(0, 1));
        let rec = &f.streams[1].alts[0];
        assert!(rec.is_in());
        assert_eq!(rec.rates, Rates::Range(8000, 48000));
        assert_eq!(rec.rates.common(), alloc::vec![8000, 16000, 22050, 32000, 44100, 48000]);
        assert_eq!(f.feature_for(rec).map(|f| f.id), Some(5));
    }

    #[test]
    fn packets_spread_the_frames() {
        assert!((0..1000).all(|n| packet_frames(48000, 1000, n) == 48));
        let total: u32 = (0..1000).map(|n| packet_frames(44100, 1000, n)).sum();
        assert_eq!(total, 44100);
        assert!((0..1000).all(|n| (44..=45).contains(&packet_frames(44100, 1000, n))));
    }

    #[test]
    fn not_audio() {
        assert!(parse(&[9, 2, 0, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0]).is_none());
    }
}
