// SPDX-License-Identifier: MIT OR Apache-2.0

//! The volume (ADR 0186): a card's playback volume and mute switch, read
//! and set through ALSA's control interface (`/dev/snd/controlC<card>`,
//! `ELEM_INFO`, `ELEM_READ`, `ELEM_WRITE`; `slate_alsa`'s numbers), as
//! `amixer` would. Both Slate's own sound and the person's PipeWire play
//! through the card, so both follow it. HD Audio cards have Master
//! Playback; USB devices PCM Playback.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_alsa::abi::*;
use slate_rt::{fs, io};

/// The elements tried, in order: the volume and its switch.
pub const ELEMENTS: [(&str, &str); 2] =
    [("Master Playback Volume", "Master Playback Switch"), ("PCM Playback Volume", "PCM Playback Switch")];

/// A card's volume now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Volume {
    pub card: u32,
    /// 0 to 1: the channels' mean between the element's least and most.
    pub level: f32,
    /// The switch off (or the level at nothing).
    pub muted: bool,
}

/// An element's id (`struct snd_ctl_elem_id`) by name: the mixer
/// interface, index 0.
pub fn elem_id(name: &str) -> [u8; ELEM_ID_SIZE] {
    let mut id = [0u8; ELEM_ID_SIZE];
    put_u32(&mut id, EID_IFACE, ELEM_IFACE_MIXER);
    put_str(&mut id, EID_NAME, EID_NAME_LEN, name);
    id
}

/// An integer element's range and channels, from `ELEM_INFO`'s answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min: i64,
    pub max: i64,
    pub count: usize,
}

impl Range {
    pub fn from_info(b: &[u8]) -> Option<Range> {
        (get_u32(b, EI_TYPE) == ELEM_TYPE_INTEGER).then(|| Range {
            min: get_u64(b, EI_INT_MIN) as i64,
            max: get_u64(b, EI_INT_MAX) as i64,
            count: (get_u32(b, EI_COUNT) as usize).clamp(1, 128),
        })
    }

    /// The level (0 to 1) of the channels' values.
    pub fn level(&self, values: &[i64]) -> f32 {
        if self.max <= self.min || values.is_empty() {
            return 0.0;
        }
        let mean = values.iter().sum::<i64>() as f32 / values.len() as f32;
        ((mean - self.min as f32) / (self.max - self.min) as f32).clamp(0.0, 1.0)
    }

    /// The value for a level (0 to 1), rounded to the nearest step.
    pub fn value(&self, level: f32) -> i64 {
        let span = (self.max - self.min) as f32;
        self.min + (level.clamp(0.0, 1.0) * span + 0.5) as i64
    }
}

fn ioctl(fd: i32, request: u32, arg: &mut [u8]) -> Result<(), String> {
    io::ioctl(fd, request, arg.as_mut_ptr() as usize).map(|_| ()).map_err(|e| String::from(e.message()))
}

/// The values of element `name` (`count` channels).
fn read_values(fd: i32, name: &str, count: usize) -> Result<Vec<i64>, String> {
    let mut b = vec![0u8; ELEM_VALUE_SIZE];
    b[..ELEM_ID_SIZE].copy_from_slice(&elem_id(name));
    ioctl(fd, CTL_IOCTL_ELEM_READ, &mut b)?;
    Ok((0..count).map(|i| get_u64(&b, EV_VALUE + 8 * i) as i64).collect())
}

fn write_values(fd: i32, name: &str, values: &[i64]) -> Result<(), String> {
    let mut b = vec![0u8; ELEM_VALUE_SIZE];
    b[..ELEM_ID_SIZE].copy_from_slice(&elem_id(name));
    for (i, v) in values.iter().enumerate() {
        put_u64(&mut b, EV_VALUE + 8 * i, *v as u64);
    }
    ioctl(fd, CTL_IOCTL_ELEM_WRITE, &mut b)
}

fn info(fd: i32, name: &str) -> Option<(Range, u32)> {
    let mut b = vec![0u8; ELEM_INFO_SIZE];
    b[..ELEM_ID_SIZE].copy_from_slice(&elem_id(name));
    ioctl(fd, CTL_IOCTL_ELEM_INFO, &mut b).ok()?;
    let count = (get_u32(&b, EI_COUNT) as usize).clamp(1, 128);
    match get_u32(&b, EI_TYPE) {
        ELEM_TYPE_INTEGER => Some((Range::from_info(&b)?, ELEM_TYPE_INTEGER)),
        ELEM_TYPE_BOOLEAN => Some((Range { min: 0, max: 1, count }, ELEM_TYPE_BOOLEAN)),
        _ => None,
    }
}

/// A card's mixer, open.
struct Mixer {
    fd: i32,
    volume: (&'static str, Range),
    switch: Option<(&'static str, Range)>,
}

impl Mixer {
    fn open(card: u32) -> Result<Mixer, String> {
        let path = alloc::format!("/dev/snd/controlC{card}");
        let fd = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0).map_err(|e| String::from(e.message()))?;
        for (vol, sw) in ELEMENTS {
            if let Some((r, ELEM_TYPE_INTEGER)) = info(fd, vol) {
                let switch = info(fd, sw).filter(|(_, t)| *t == ELEM_TYPE_BOOLEAN).map(|(r, _)| (sw, r));
                return Ok(Mixer { fd, volume: (vol, r), switch });
            }
        }
        let _ = io::close(fd);
        Err(String::from("it has no playback volume"))
    }

    fn get(&self, card: u32) -> Result<Volume, String> {
        let (name, r) = self.volume;
        let level = r.level(&read_values(self.fd, name, r.count)?);
        let off = match self.switch {
            Some((sw, s)) => read_values(self.fd, sw, s.count)?.iter().all(|v| *v == 0),
            None => false,
        };
        Ok(Volume { card, level, muted: off || level <= 0.0 })
    }
}

impl Drop for Mixer {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

/// Card `card`'s volume.
pub fn get(card: u32) -> Result<Volume, String> {
    Mixer::open(card)?.get(card)
}

/// Set card `card`'s level (0 to 1) and switch, either or both; returns
/// the volume after. A level above nothing switches it on.
pub fn set(card: u32, level: Option<f32>, muted: Option<bool>) -> Result<Volume, String> {
    let m = Mixer::open(card)?;
    if let Some(l) = level {
        let (name, r) = m.volume;
        write_values(m.fd, name, &vec![r.value(l); r.count])?;
    }
    let on = match (muted, level) {
        (Some(mu), _) => Some(!mu),
        (None, Some(l)) if l > 0.0 => Some(true),
        _ => None,
    };
    if let (Some(on), Some((sw, s))) = (on, m.switch) {
        write_values(m.fd, sw, &vec![i64::from(on); s.count])?;
    }
    m.get(card)
}

/// The card the desktop's volume is: the first one there is.
pub fn default_card() -> Option<u32> {
    crate::cards().first().map(|c| c.index)
}

/// "64%", or "muted".
pub fn words(v: &Volume) -> String {
    if v.muted { String::from("muted") } else { alloc::format!("{}%", percent(v.level)) }
}

/// A level as a whole percentage.
pub fn percent(level: f32) -> u32 {
    (level.clamp(0.0, 1.0) * 100.0 + 0.5) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_levels() {
        let id = elem_id("Master Playback Volume");
        assert_eq!(get_u32(&id, EID_IFACE), ELEM_IFACE_MIXER);
        assert_eq!(get_str(&id, EID_NAME, EID_NAME_LEN), b"Master Playback Volume");
        assert_eq!(get_u32(&id, EID_NUMID), 0);
        // HD Audio's 0 to 127, two channels.
        let r = Range { min: 0, max: 127, count: 2 };
        assert_eq!(r.level(&[127, 127]), 1.0);
        assert_eq!(r.level(&[0, 0]), 0.0);
        assert!((r.level(&[63, 64]) - 0.5).abs() < 0.01);
        assert_eq!(r.value(0.5), 64);
        assert_eq!(r.value(1.5), 127);
        assert_eq!(r.value(-1.0), 0);
        // A USB device's range in dB steps, below zero.
        let u = Range { min: -10240, max: 0, count: 1 };
        assert_eq!(u.value(0.0), -10240);
        assert_eq!(u.value(1.0), 0);
        assert!((u.level(&[-5120]) - 0.5).abs() < 0.001);
        assert_eq!(percent(0.644), 64);
        assert_eq!(words(&Volume { card: 0, level: 0.5, muted: false }), "50%");
        assert_eq!(words(&Volume { card: 0, level: 0.5, muted: true }), "muted");
    }

    #[test]
    fn info_is_read() {
        let mut b = vec![0u8; ELEM_INFO_SIZE];
        put_u32(&mut b, EI_TYPE, ELEM_TYPE_INTEGER);
        put_u32(&mut b, EI_COUNT, 2);
        put_u64(&mut b, EI_INT_MIN, 0);
        put_u64(&mut b, EI_INT_MAX, 127);
        assert_eq!(Range::from_info(&b), Some(Range { min: 0, max: 127, count: 2 }));
        put_u32(&mut b, EI_TYPE, ELEM_TYPE_BOOLEAN);
        assert_eq!(Range::from_info(&b), None);
    }
}
