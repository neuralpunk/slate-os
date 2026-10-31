// SPDX-License-Identifier: MIT OR Apache-2.0

//! Playing through ALSA's kernel interface, as alsa-lib does for a `hw:`
//! device (ADR 0184): open `/dev/snd/pcmC<card>D0p`, refine and set the
//! hardware parameters, set the thresholds, prepare, write the frames,
//! drain. The numbers and layouts are `slate_alsa::abi`'s.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_alsa::abi::*;
use slate_alsa::params::{HwParams, Interval, Mask};
use slate_rt::errno::Errno;
use slate_rt::{fs, io};

/// Why a tune didn't play.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// Another program has the card (one opener at a time, as on Linux).
    Busy,
    Other(String),
}

fn ioctl(fd: i32, request: u32, arg: &mut [u8]) -> Result<usize, Errno> {
    io::ioctl(fd, request, arg.as_mut_ptr() as usize)
}

/// Set the hardware to `rate` and `channels`, 16-bit interleaved, with
/// periods of about 20 ms. Returns the buffer's size in frames.
fn hw_params(fd: i32, rate: u32, channels: u32) -> Result<u64, Errno> {
    let mut raw = alloc::vec![0u8; HW_PARAMS_SIZE];
    let mut p = HwParams::any();
    *p.mask_mut(HW_PARAM_ACCESS) = Mask::of(&[ACCESS_RW_INTERLEAVED]);
    *p.mask_mut(HW_PARAM_FORMAT) = Mask::of(&[FORMAT_S16_LE]);
    *p.interval_mut(HW_PARAM_CHANNELS) = Interval::value(channels);
    *p.interval_mut(HW_PARAM_RATE) = Interval::value(rate);
    p.encode(&mut raw);
    ioctl(fd, PCM_IOCTL_HW_REFINE, &mut raw)?;
    let mut p = HwParams::decode(&raw);
    // About a fiftieth of a second a period, four of them, within what the
    // card allows.
    let want = u64::from(rate / 50).max(1) as u32;
    let size = *p.interval(HW_PARAM_PERIOD_SIZE);
    let period = want.clamp(size.least(), size.most().max(size.least()));
    let _ = p.interval_mut(HW_PARAM_PERIOD_SIZE).refine(&Interval::value(period));
    let periods = *p.interval(HW_PARAM_PERIODS);
    let _ = p
        .interval_mut(HW_PARAM_PERIODS)
        .refine(&Interval::value(4u32.clamp(periods.least(), periods.most().max(periods.least()))));
    p.rmask = !0;
    p.encode(&mut raw);
    ioctl(fd, PCM_IOCTL_HW_PARAMS, &mut raw)?;
    let p = HwParams::decode(&raw);
    Ok(u64::from(p.get(HW_PARAM_BUFFER_SIZE).unwrap_or(period * 4)))
}

/// Start when the buffer is full, stop only on an underrun.
fn sw_params(fd: i32, buffer: u64) -> Result<(), Errno> {
    let mut raw = alloc::vec![0u8; SW_PARAMS_SIZE];
    put_u32(&mut raw, SWP_TSTAMP_TYPE, TSTAMP_TYPE_MONOTONIC);
    put_u32(&mut raw, SWP_PERIOD_STEP, 1);
    put_u64(&mut raw, SWP_AVAIL_MIN, (buffer / 4).max(1));
    put_u64(&mut raw, SWP_START_THRESHOLD, buffer);
    put_u64(&mut raw, SWP_STOP_THRESHOLD, buffer);
    ioctl(fd, PCM_IOCTL_SW_PARAMS, &mut raw).map(|_| ())
}

/// Write `frames` interleaved frames of `channels` samples (blocking).
fn write_all(fd: i32, samples: &[i16], channels: u32) -> Result<(), Errno> {
    let per = channels as usize;
    let mut done = 0;
    let total = samples.len() / per;
    while done < total {
        let chunk = &samples[done * per..];
        let mut x = [0u8; XFERI_SIZE];
        put_u64(&mut x, 8, chunk.as_ptr() as u64);
        put_u64(&mut x, 16, (total - done) as u64);
        match ioctl(fd, PCM_IOCTL_WRITEI_FRAMES, &mut x) {
            Ok(_) => done += get_u64(&x, 0) as usize,
            Err(Errno::EINTR) => {}
            // An underrun (the program was held up): prepare and go on.
            Err(Errno::EPIPE) => {
                ioctl(fd, PCM_IOCTL_PREPARE, &mut [])?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Play the test tune on card `card`'s first playback device. Returns the
/// rate it played at.
pub fn tune(card: u32) -> Result<u32, Failure> {
    let path = format!("/dev/snd/pcmC{card}D0p");
    let fd = match fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(Errno::EBUSY) => return Err(Failure::Busy),
        Err(Errno::EACCES) => {
            return Err(Failure::Other(String::from(
                "you may not use the sound cards (Settings › Users › \"Can use the desktop\")",
            )));
        }
        Err(e) => return Err(Failure::Other(format!("{path}: {}", e.message()))),
    };
    let r = (|| {
        // The usual rates and layouts, in order.
        let mut last = Errno::EINVAL;
        for (rate, channels) in [(48000, 2), (44100, 2), (48000, 1), (44100, 1)] {
            match hw_params(fd, rate, channels) {
                Ok(buffer) => {
                    sw_params(fd, buffer).map_err(|e| format!("its settings: {}", e.message()))?;
                    ioctl(fd, PCM_IOCTL_PREPARE, &mut []).map_err(|e| format!("preparing: {}", e.message()))?;
                    let samples: Vec<i16> = crate::tune::render(rate, channels);
                    write_all(fd, &samples, channels).map_err(|e| format!("playing: {}", e.message()))?;
                    ioctl(fd, PCM_IOCTL_DRAIN, &mut []).map_err(|e| format!("finishing: {}", e.message()))?;
                    return Ok(rate);
                }
                Err(e) => last = e,
            }
        }
        Err(format!("it takes none of 48 or 44.1 kHz, 16-bit, stereo or mono ({})", last.message()))
    })();
    let _ = io::close(fd);
    r.map_err(Failure::Other)
}
