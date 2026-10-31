// SPDX-License-Identifier: MIT OR Apache-2.0

//! PCM streams: `/dev/snd/pcmCnDd[pc]` (ADR 0184).
//!
//! One substream per direction, opened by one program at a time (EBUSY
//! otherwise, as `hw:` devices are on Linux). The program sets the
//! hardware parameters (refined by `slate_alsa::params` within what the
//! driver allows), then writes or reads frames through `WRITEI`/`READI`
//! or through the mapped buffer, whose position the mapped control page
//! (`appl_ptr`) or `SYNC_PTR` tells the kernel. The driver moves the
//! hardware's position and calls [`Substream::period_elapsed`]; the
//! stream starts at the start threshold, stops on an underrun or overrun
//! (XRUN) at the stop threshold, and drains to the program's position.
//! Behaviour follows alsa-lib's documentation of the states and the
//! software parameters; the code is Slate's own.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use slate_alsa::abi::*;
use slate_alsa::params::{self, Hardware, HwParams, Setup};
use slate_alsa::ptr;

use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::vfs::{self, Inode, Metadata, Result};
use crate::fs::{File, O_NONBLOCK, POLLERR, POLLIN, POLLOUT};
use crate::mm::{PAGE_SIZE, PhysAddr, frame};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// What a driver does for a stream. Called with the stream's lock held
/// (interrupts masked): none of these may sleep.
pub trait PcmOps: Send + Sync {
    /// What the hardware allows.
    fn hardware(&self) -> Hardware;
    /// Set the hardware up for `setup` when a program sets its parameters:
    /// called without the stream's lock, so it may sleep (USB's control
    /// transfers).
    fn configure(&self, _setup: &Setup) -> Result<()> {
        Ok(())
    }
    /// Get ready to play or record `setup` from `buf` (its frames hold the
    /// whole buffer, from offset 0), position at 0.
    fn prepare(&self, setup: &Setup, buf: &Arc<Pages>) -> Result<()>;
    fn start(&self);
    /// Stop; the position stays where it is.
    fn stop(&self);
    /// Frames from the buffer's start the hardware has reached (0 to the
    /// buffer size).
    fn position(&self) -> u32;
    /// The configuration is no longer needed (hw_free, close).
    fn release(&self) {}
}

/// Pages a stream shares with the program that maps them: the buffer,
/// the status page, the control page. Each is a refcounted user page, so
/// a mapping keeps it after the stream lets go.
pub struct Pages {
    frames: Vec<PhysAddr>,
}

impl Drop for Pages {
    fn drop(&mut self) {
        for f in &self.frames {
            frame::put_user_page(*f);
        }
    }
}

impl Pages {
    pub fn new(bytes: usize) -> Result<Arc<Pages>> {
        let n = bytes.div_ceil(PAGE_SIZE as usize).max(1);
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            match frame::alloc_user_page() {
                Some(f) => frames.push(f),
                None => {
                    for f in frames {
                        frame::put_user_page(f);
                    }
                    return Err(ENOMEM);
                }
            }
        }
        Ok(Arc::new(Pages { frames }))
    }

    /// The physical pages, for the hardware's descriptors.
    pub fn frames(&self) -> &[PhysAddr] {
        &self.frames
    }

    /// The kernel's address of byte `off` and how many bytes follow it in
    /// the same page.
    fn at(&self, off: usize) -> (*mut u8, usize) {
        let page = PAGE_SIZE as usize;
        let f = self.frames[off / page];
        // SAFETY: In the direct map; the page is ours while `self` lives.
        (unsafe { f.to_virt().add(off % page) }, page - off % page)
    }

    pub fn read_u64(&self, off: usize) -> u64 {
        let (p, _) = self.at(off);
        // SAFETY: Aligned (offsets are multiples of 8), inside a page we
        // own; the program may write it at any time, hence volatile.
        unsafe { p.cast::<u64>().read_volatile() }
    }

    pub fn write_u64(&self, off: usize, v: u64) {
        let (p, _) = self.at(off);
        // SAFETY: As in `read_u64`.
        unsafe { p.cast::<u64>().write_volatile(v) }
    }

    pub fn write_u32(&self, off: usize, v: u32) {
        let (p, _) = self.at(off);
        // SAFETY: As in `read_u64`, 4-byte aligned.
        unsafe { p.cast::<u32>().write_volatile(v) }
    }

    /// Zero `len` bytes from `off`.
    pub fn zero(&self, mut off: usize, mut len: usize) {
        while len > 0 {
            let (p, room) = self.at(off);
            let n = room.min(len);
            // SAFETY: Inside a page we own.
            unsafe { core::ptr::write_bytes(p, 0, n) };
            off += n;
            len -= n;
        }
    }

    /// Copy `len` bytes between the program's `user` and byte `off`.
    fn user_copy(&self, mut off: usize, mut user: u64, mut len: usize, from_user: bool) -> Result<()> {
        while len > 0 {
            let (p, room) = self.at(off);
            let n = room.min(len);
            // SAFETY: `n` bytes of a page we own; the program writes the
            // buffer through its mapping only as alsa-lib's protocol allows.
            let page = unsafe { core::slice::from_raw_parts_mut(p, n) };
            if from_user {
                copy_from_user(page, user).map_err(|_| EFAULT)?;
            } else {
                copy_to_user(user, page).map_err(|_| EFAULT)?;
            }
            off += n;
            user += n as u64;
            len -= n;
        }
        Ok(())
    }

    /// Copy bytes out (a driver filling its own transfer buffers).
    pub fn read(&self, mut off: usize, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            let (p, room) = self.at(off);
            let n = room.min(out.len() - done);
            // SAFETY: Inside a page we own.
            unsafe { core::ptr::copy_nonoverlapping(p, out[done..].as_mut_ptr(), n) };
            off += n;
            done += n;
        }
    }

    /// Copy bytes in (a driver delivering recorded frames).
    #[allow(dead_code)] // USB audio (next).
    pub fn write(&self, mut off: usize, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let (p, room) = self.at(off);
            let n = room.min(data.len() - done);
            // SAFETY: Inside a page we own.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), p, n) };
            off += n;
            done += n;
        }
    }
}

/// The pages for `mmap`: file offsets with the high bits masked off are
/// offsets in them.
struct MapSource(Arc<Pages>);

impl Inode for MapSource {
    fn metadata(&self) -> Metadata {
        Metadata { mode: vfs::S_IFREG | 0o600, nlink: 1, ..Metadata::default() }
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn shared_mmap(&self) -> bool {
        true
    }
    fn shared_page(&self, offset: u64) -> Result<PhysAddr> {
        let f = *self.0.frames.get(((offset & 0x00ff_ffff) / PAGE_SIZE) as usize).ok_or(EFAULT)?;
        frame::get_user_page(f);
        Ok(f)
    }
}

/// The software parameters (`struct snd_pcm_sw_params`).
#[derive(Clone, Copy, Debug)]
struct Sw {
    tstamp_mode: u32,
    period_step: u32,
    start_threshold: u64,
    stop_threshold: u64,
    silence_threshold: u64,
    silence_size: u64,
    boundary: u64,
    tstamp_type: u32,
}

/// An open stream's state.
struct Run {
    state: u32,
    setup: Option<Setup>,
    buf: Option<Arc<Pages>>,
    /// The mapped status and control pages; the control page holds the
    /// program's position and avail_min, which the program may write.
    status: Arc<Pages>,
    control: Arc<Pages>,
    sw: Sw,
    /// The hardware's position at the start of the buffer's current lap,
    /// and where in the buffer it was last seen.
    hw_base: u64,
    last_pos: u64,
    avail_max: u64,
    trigger_ns: u64,
    /// Playback: how far the frames after the played ones were silenced.
    silenced_to: u64,
    user_pversion: u32,
}

impl Run {
    fn hw_ptr(&self) -> u64 {
        self.status.read_u64(MS_HW_PTR)
    }
    fn appl(&self) -> u64 {
        self.control.read_u64(MC_APPL_PTR)
    }
    fn set_appl(&self, v: u64) {
        self.control.write_u64(MC_APPL_PTR, v);
    }
    fn avail_min(&self) -> u64 {
        self.control.read_u64(MC_AVAIL_MIN).max(1)
    }
    fn set_state(&mut self, s: u32) {
        self.state = s;
        self.status.write_u32(MS_STATE, s);
    }
}

/// A stream of a PCM device.
pub struct Substream {
    pub device: u32,
    pub dir: u32,
    pub name: String,
    card: AtomicU32,
    ops: Arc<dyn PcmOps>,
    run: IrqSpinLock<Option<Run>>,
    wait: WaitQueue,
    events: AtomicU64,
    opened: AtomicBool,
    gone: AtomicBool,
}

impl Substream {
    pub fn new(device: u32, dir: u32, name: &str, ops: Arc<dyn PcmOps>) -> Arc<Substream> {
        Arc::new(Substream {
            device,
            dir,
            name: name.into(),
            card: AtomicU32::new(0),
            ops,
            run: IrqSpinLock::new(None),
            wait: WaitQueue::new(),
            events: AtomicU64::new(0),
            opened: AtomicBool::new(false),
            gone: AtomicBool::new(false),
        })
    }

    pub(super) fn attach(&self, card: u32) {
        self.card.store(card, Ordering::Relaxed);
    }

    fn playback(&self) -> bool {
        self.dir == STREAM_PLAYBACK
    }

    /// Wake whoever waits on the stream.
    fn notify(&self) {
        self.events.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }

    /// The device went: programs see DISCONNECTED and ENODEV.
    pub(super) fn disconnect(&self) {
        self.gone.store(true, Ordering::Release);
        if let Some(r) = self.run.lock().as_mut() {
            r.set_state(STATE_DISCONNECTED);
        }
        self.notify();
    }

    /// The hardware finished a period (from its interrupt, or a driver's
    /// thread): bring the position up to date, wake waiters.
    pub fn period_elapsed(&self) {
        {
            let mut g = self.run.lock();
            let Some(r) = g.as_mut() else { return };
            self.update(r);
        }
        self.notify();
    }

    fn avail(&self, r: &Run) -> u64 {
        let Some(s) = r.setup else { return 0 };
        let b = r.sw.boundary;
        let a = if self.playback() {
            ptr::playback_avail(r.hw_ptr(), r.appl(), u64::from(s.buffer_size), b)
        } else {
            ptr::capture_avail(r.hw_ptr(), r.appl(), b)
        };
        a.max(0) as u64
    }

    /// Frames queued for the hardware (playback) or recorded and unread.
    fn queued(&self, r: &Run) -> u64 {
        let Some(s) = r.setup else { return 0 };
        if self.playback() { u64::from(s.buffer_size).saturating_sub(self.avail(r)) } else { self.avail(r) }
    }

    /// Read the hardware's position and act on it: underruns and overruns,
    /// the end of a drain, silence after what was played.
    fn update(&self, r: &mut Run) {
        if !matches!(r.state, STATE_RUNNING | STATE_DRAINING) {
            return;
        }
        let Some(s) = r.setup else { return };
        let size = u64::from(s.buffer_size);
        let pos = u64::from(self.ops.position()) % size;
        if pos < r.last_pos {
            r.hw_base = ptr::advance(r.hw_base, size, r.sw.boundary);
        }
        r.last_pos = pos;
        let hw = ptr::advance(r.hw_base, pos, r.sw.boundary);
        r.status.write_u64(MS_HW_PTR, hw);
        self.stamp(r);
        let avail = self.avail(r);
        r.avail_max = r.avail_max.max(avail);
        if self.playback() {
            if r.state == STATE_DRAINING {
                if avail >= size {
                    self.ops.stop();
                    r.set_state(STATE_SETUP);
                    r.trigger_ns = crate::time::monotonic_ns();
                }
            } else if avail >= r.sw.stop_threshold {
                self.xrun(r);
                return;
            }
            self.silence(r, &s);
        } else if avail >= r.sw.stop_threshold {
            self.xrun(r);
        }
    }

    fn xrun(&self, r: &mut Run) {
        self.ops.stop();
        r.set_state(STATE_XRUN);
        r.trigger_ns = crate::time::monotonic_ns();
    }

    /// The status page's timestamp.
    fn stamp(&self, r: &Run) {
        let ns = if r.sw.tstamp_type == TSTAMP_TYPE_GETTIMEOFDAY {
            crate::time::realtime_ns().max(0) as u64
        } else {
            crate::time::monotonic_ns()
        };
        r.status.write_u64(MS_TSTAMP, ns / 1_000_000_000);
        r.status.write_u64(MS_TSTAMP + 8, ns % 1_000_000_000);
    }

    /// Silence for playback (sw_params): with a silence size of the
    /// boundary or more, everything played is zeroed at once, so stale
    /// frames never play twice; else, while fewer than the threshold are
    /// queued, up to the silence size after the program's frames.
    fn silence(&self, r: &mut Run, s: &Setup) {
        let Some(buf) = r.buf.clone() else { return };
        let size = u64::from(s.buffer_size);
        let fb = s.frame_bytes as usize;
        let zero = |from: u64, n: u64| {
            let mut at = from % size;
            let mut left = n.min(size);
            while left > 0 {
                let k = left.min(size - at);
                buf.zero(at as usize * fb, k as usize * fb);
                at = (at + k) % size;
                left -= k;
            }
        };
        if r.sw.silence_size >= r.sw.boundary {
            let hw = r.hw_ptr();
            let n = ptr::distance(hw, r.silenced_to, r.sw.boundary).min(size);
            zero(r.silenced_to, n);
            r.silenced_to = hw;
        } else if r.sw.silence_threshold > 0 && self.queued(r) < r.sw.silence_threshold {
            let appl = r.appl();
            let from = if ptr::distance(r.silenced_to, appl, r.sw.boundary) < size { r.silenced_to } else { appl };
            let room = self.avail(r).min(r.sw.silence_size);
            let done = ptr::distance(from, appl, r.sw.boundary);
            if room > done {
                zero(from, room - done);
                r.silenced_to = ptr::advance(from, room - done, r.sw.boundary);
            }
        }
    }

    fn start_locked(&self, r: &mut Run) -> Result<()> {
        if r.state != STATE_PREPARED {
            return Err(EBADFD);
        }
        if self.playback() && self.queued(r) == 0 {
            return Err(EPIPE);
        }
        r.set_state(STATE_RUNNING);
        r.trigger_ns = crate::time::monotonic_ns();
        self.ops.start();
        Ok(())
    }

    /// A wait's limit: long enough for a period (twice), so a stream
    /// whose interrupts don't come still moves (it is polled).
    fn wait_ns(r: &Run) -> u64 {
        let period_ns = r.setup.map_or(10_000_000, |s| u64::from(s.period_size) * 1_000_000_000 / u64::from(s.rate));
        crate::time::monotonic_ns() + 2 * period_ns + 2_000_000
    }

    /// Wait until `ready` or the deadline, then update from the hardware.
    /// Err(EINTR) on a signal.
    fn wait_for(&self, ready: impl Fn(&Self, &Run) -> bool) -> Result<()> {
        let deadline = match self.run.lock().as_ref() {
            Some(r) => Self::wait_ns(r),
            None => return Err(EBADFD),
        };
        let res = self.wait.wait_until_deadline(
            || self.gone.load(Ordering::Acquire) || self.run.lock().as_ref().is_none_or(|r| ready(self, r)),
            deadline,
        );
        if let Some(r) = self.run.lock().as_mut() {
            self.update(r);
        }
        if res == crate::sched::wait::WaitResult::Interrupted { Err(EINTR) } else { Ok(()) }
    }

    /// `WRITEI_FRAMES`: frames from the program's `buf` into the buffer.
    fn write_frames(&self, user: u64, frames: u64, nonblock: bool) -> Result<u64> {
        let mut done = 0u64;
        while done < frames {
            let (buf, off, n, fb) = {
                let mut g = self.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                self.update(r);
                match r.state {
                    STATE_PREPARED | STATE_RUNNING | STATE_PAUSED => {}
                    STATE_XRUN => return if done > 0 { Ok(done) } else { Err(EPIPE) },
                    STATE_DISCONNECTED => return Err(ENODEV),
                    _ => return Err(EBADFD),
                }
                let s = r.setup.ok_or(EBADFD)?;
                let avail = self.avail(r);
                if avail == 0 {
                    // Full: a stream that won't start never empties.
                    if nonblock || r.state != STATE_RUNNING {
                        return if done > 0 { Ok(done) } else { Err(EAGAIN) };
                    }
                    drop(g);
                    self.wait_for(|me, r| me.avail(r) > 0 || r.state != STATE_RUNNING)?;
                    continue;
                }
                let size = u64::from(s.buffer_size);
                let at = r.appl() % size;
                let n = (frames - done).min(avail).min(size - at);
                (r.buf.clone().ok_or(EBADFD)?, at as usize * s.frame_bytes as usize, n, s.frame_bytes as u64)
            };
            buf.user_copy(off, user + done * fb, (n * fb) as usize, true)?;
            let mut g = self.run.lock();
            let r = g.as_mut().ok_or(EBADFD)?;
            let appl = ptr::advance(r.appl(), n, r.sw.boundary);
            r.set_appl(appl);
            done += n;
            if r.state == STATE_PREPARED && self.queued(r) >= r.sw.start_threshold {
                self.start_locked(r)?;
            }
        }
        Ok(done)
    }

    /// `READI_FRAMES`: recorded frames to the program's `buf`.
    fn read_frames(&self, user: u64, frames: u64, nonblock: bool) -> Result<u64> {
        let mut done = 0u64;
        while done < frames {
            let (buf, off, n, fb) = {
                let mut g = self.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                if r.state == STATE_PREPARED && frames >= r.sw.start_threshold {
                    self.start_locked(r)?;
                }
                self.update(r);
                match r.state {
                    STATE_RUNNING | STATE_PAUSED | STATE_DRAINING | STATE_PREPARED => {}
                    STATE_XRUN => return if done > 0 { Ok(done) } else { Err(EPIPE) },
                    STATE_DISCONNECTED => return Err(ENODEV),
                    _ => return Err(EBADFD),
                }
                let s = r.setup.ok_or(EBADFD)?;
                let avail = self.avail(r);
                if avail == 0 {
                    if nonblock || r.state != STATE_RUNNING {
                        return if done > 0 { Ok(done) } else { Err(EAGAIN) };
                    }
                    drop(g);
                    self.wait_for(|me, r| me.avail(r) > 0 || r.state != STATE_RUNNING)?;
                    continue;
                }
                let size = u64::from(s.buffer_size);
                let at = r.appl() % size;
                let n = (frames - done).min(avail).min(size - at);
                (r.buf.clone().ok_or(EBADFD)?, at as usize * s.frame_bytes as usize, n, s.frame_bytes as u64)
            };
            buf.user_copy(off, user + done * fb, (n * fb) as usize, false)?;
            let mut g = self.run.lock();
            let r = g.as_mut().ok_or(EBADFD)?;
            let appl = ptr::advance(r.appl(), n, r.sw.boundary);
            r.set_appl(appl);
            done += n;
        }
        Ok(done)
    }

    /// `HW_REFINE` and `HW_PARAMS`.
    fn hw_params(&self, arg: u64, set: bool) -> Result<u64> {
        let mut raw = [0u8; HW_PARAMS_SIZE];
        copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
        let mut p = HwParams::decode(&raw);
        let hw = self.ops.hardware();
        if !set {
            params::refine(&mut p, &hw).map_err(|_| EINVAL)?;
            p.encode(&mut raw);
            copy_to_user(arg, &raw).map_err(|_| EFAULT)?;
            return Ok(0);
        }
        params::choose(&mut p, &hw).map_err(|_| EINVAL)?;
        let setup = Setup::from(&p).ok_or(EINVAL)?;
        {
            let g = self.run.lock();
            let r = g.as_ref().ok_or(EBADFD)?;
            if !matches!(r.state, STATE_OPEN | STATE_SETUP | STATE_PREPARED) {
                return Err(EBADFD);
            }
        }
        self.ops.configure(&setup)?;
        let buf = Pages::new(setup.buffer_bytes())?;
        {
            let mut g = self.run.lock();
            let r = g.as_mut().ok_or(EBADFD)?;
            self.ops.release();
            let size = u64::from(setup.buffer_size);
            r.setup = Some(setup);
            r.buf = Some(buf);
            r.sw = Sw {
                tstamp_mode: 0,
                period_step: 1,
                start_threshold: 1,
                stop_threshold: size,
                silence_threshold: 0,
                silence_size: 0,
                boundary: ptr::boundary(size),
                tstamp_type: r.sw.tstamp_type,
            };
            r.control.write_u64(MC_AVAIL_MIN, u64::from(setup.period_size));
            r.set_state(STATE_SETUP);
        }
        p.encode(&mut raw);
        copy_to_user(arg, &raw).map_err(|_| EFAULT)?;
        crate::log_debug!(
            "sound: {}: {} Hz, {} channels, format {}, period {} frames x {}",
            self.name,
            setup.rate,
            setup.channels,
            setup.format,
            setup.period_size,
            setup.periods
        );
        Ok(0)
    }

    fn sw_params(&self, arg: u64) -> Result<u64> {
        let mut raw = [0u8; SW_PARAMS_SIZE];
        copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        let s = r.setup.ok_or(EBADFD)?;
        if r.state == STATE_OPEN {
            return Err(EBADFD);
        }
        let size = u64::from(s.buffer_size);
        let avail_min = get_u64(&raw, SWP_AVAIL_MIN);
        let silence_size = get_u64(&raw, SWP_SILENCE_SIZE);
        let silence_threshold = get_u64(&raw, SWP_SILENCE_THRESHOLD);
        let tstamp_type = get_u32(&raw, SWP_TSTAMP_TYPE);
        // Each silence setting fits the buffer (or the size is the
        // boundary: silence whatever was played). alsa-lib's drain sets a
        // threshold of the whole buffer with a size beside it.
        if tstamp_type > TSTAMP_TYPE_MONOTONIC_RAW
            || silence_threshold > size
            || (silence_size < r.sw.boundary && silence_size > size)
        {
            return Err(EINVAL);
        }
        let avail_min = avail_min.max(1);
        r.sw.tstamp_mode = get_u32(&raw, SWP_TSTAMP_MODE);
        r.sw.period_step = get_u32(&raw, SWP_PERIOD_STEP);
        r.sw.start_threshold = get_u64(&raw, SWP_START_THRESHOLD);
        r.sw.stop_threshold = get_u64(&raw, SWP_STOP_THRESHOLD);
        r.sw.silence_threshold = silence_threshold;
        r.sw.silence_size = silence_size;
        r.sw.tstamp_type = tstamp_type;
        r.control.write_u64(MC_AVAIL_MIN, avail_min);
        // The boundary is the kernel's to say.
        put_u64(&mut raw, SWP_BOUNDARY, r.sw.boundary);
        put_u32(&mut raw, SWP_PROTO, PCM_VERSION);
        drop(g);
        copy_to_user(arg, &raw).map_err(|_| EFAULT)?;
        Ok(0)
    }

    fn prepare(&self) -> Result<u64> {
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        match r.state {
            STATE_OPEN => return Err(EBADFD),
            STATE_DISCONNECTED => return Err(ENODEV),
            STATE_RUNNING | STATE_DRAINING | STATE_PAUSED => self.ops.stop(),
            _ => {}
        }
        let s = r.setup.ok_or(EBADFD)?;
        let buf = r.buf.clone().ok_or(EBADFD)?;
        self.ops.prepare(&s, &buf)?;
        r.hw_base = 0;
        r.last_pos = 0;
        r.avail_max = 0;
        r.silenced_to = 0;
        r.status.write_u64(MS_HW_PTR, 0);
        r.set_appl(0);
        if self.playback() && r.sw.silence_size >= r.sw.boundary {
            buf.zero(0, s.buffer_bytes());
        }
        r.set_state(STATE_PREPARED);
        drop(g);
        self.notify();
        Ok(0)
    }

    fn drop_stream(&self) -> Result<u64> {
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        match r.state {
            STATE_OPEN => return Err(EBADFD),
            STATE_DISCONNECTED => return Err(ENODEV),
            STATE_RUNNING | STATE_DRAINING | STATE_PAUSED => self.ops.stop(),
            _ => {}
        }
        if r.state != STATE_SETUP {
            r.trigger_ns = crate::time::monotonic_ns();
        }
        r.set_state(STATE_SETUP);
        drop(g);
        self.notify();
        Ok(0)
    }

    fn drain(&self, nonblock: bool) -> Result<u64> {
        {
            let mut g = self.run.lock();
            let r = g.as_mut().ok_or(EBADFD)?;
            match r.state {
                STATE_OPEN | STATE_SETUP => return Err(EBADFD),
                STATE_DISCONNECTED => return Err(ENODEV),
                _ => {}
            }
            if !self.playback() {
                // Capture: stop; what was recorded stays readable.
                if r.state == STATE_RUNNING {
                    self.update(r);
                    self.ops.stop();
                }
                r.set_state(STATE_SETUP);
                drop(g);
                self.notify();
                return Ok(0);
            }
            if r.state == STATE_PREPARED {
                if self.queued(r) == 0 {
                    r.set_state(STATE_SETUP);
                    return Ok(0);
                }
                self.start_locked(r)?;
            }
            if r.state == STATE_XRUN {
                r.set_state(STATE_SETUP);
                return Ok(0);
            }
            if r.state == STATE_RUNNING || r.state == STATE_PAUSED {
                if r.state == STATE_PAUSED {
                    self.ops.start();
                }
                // What lies past the program's frames is silenced, so the
                // end of the drain plays nothing stale.
                if let (Some(s), Some(buf)) = (r.setup, r.buf.clone()) {
                    let size = u64::from(s.buffer_size);
                    let mut at = r.appl() % size;
                    let mut left = self.avail(r);
                    while left > 0 {
                        let k = left.min(size - at);
                        buf.zero(at as usize * s.frame_bytes as usize, k as usize * s.frame_bytes as usize);
                        at = (at + k) % size;
                        left -= k;
                    }
                }
                r.set_state(STATE_DRAINING);
            }
        }
        if nonblock {
            return Err(EAGAIN);
        }
        loop {
            {
                let g = self.run.lock();
                let r = g.as_ref().ok_or(EBADFD)?;
                if r.state != STATE_DRAINING {
                    return if r.state == STATE_DISCONNECTED { Err(ENODEV) } else { Ok(0) };
                }
            }
            self.wait_for(|_, r| r.state != STATE_DRAINING)?;
        }
    }

    fn pause(&self, on: bool) -> Result<u64> {
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        match (r.state, on) {
            (STATE_RUNNING, true) => {
                self.update(r);
                self.ops.stop();
                r.set_state(STATE_PAUSED);
            }
            (STATE_PAUSED, false) => {
                self.ops.start();
                r.set_state(STATE_RUNNING);
            }
            _ => return Err(EBADFD),
        }
        r.trigger_ns = crate::time::monotonic_ns();
        drop(g);
        self.notify();
        Ok(0)
    }

    /// `REWIND` (back) and `FORWARD`: move the program's position within
    /// what it may, writing back how far it went.
    fn move_appl(&self, arg: u64, back: bool) -> Result<u64> {
        let want: u64 = read_user(arg).map_err(|_| EFAULT)?;
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        if !matches!(r.state, STATE_PREPARED | STATE_RUNNING | STATE_PAUSED | STATE_DRAINING) {
            return Err(EBADFD);
        }
        self.update(r);
        let room = if back { self.queued(r) } else { self.avail(r) };
        let n = want.min(room);
        let b = r.sw.boundary;
        let appl = if back { ptr::advance(r.appl(), b - n, b) } else { ptr::advance(r.appl(), n, b) };
        r.set_appl(appl);
        drop(g);
        write_user(arg, &n).map_err(|_| EFAULT)?;
        Ok(0)
    }

    /// `STATUS` and `STATUS_EXT`.
    fn status(&self, arg: u64, ext: bool) -> Result<u64> {
        let mut raw = [0u8; STATUS_SIZE];
        if ext {
            copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
        }
        let audio_data = get_u32(&raw, ST_AUDIO_TSTAMP_DATA);
        raw.fill(0);
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        self.update(r);
        let ns = |v: u64, raw: &mut [u8], off: usize| {
            put_u64(raw, off, v / 1_000_000_000);
            put_u64(raw, off + 8, v % 1_000_000_000);
        };
        put_u32(&mut raw, ST_STATE, r.state);
        ns(r.trigger_ns, &mut raw, ST_TRIGGER_TSTAMP);
        let now = if r.sw.tstamp_type == TSTAMP_TYPE_GETTIMEOFDAY {
            crate::time::realtime_ns().max(0) as u64
        } else {
            crate::time::monotonic_ns()
        };
        ns(now, &mut raw, ST_TSTAMP);
        ns(now, &mut raw, ST_DRIVER_TSTAMP);
        put_u64(&mut raw, ST_APPL_PTR, r.appl());
        put_u64(&mut raw, ST_HW_PTR, r.hw_ptr());
        let running = matches!(r.state, STATE_RUNNING | STATE_DRAINING | STATE_PAUSED);
        let delay = if running { self.queued(r) } else { 0 };
        put_u64(&mut raw, ST_DELAY, delay);
        put_u64(&mut raw, ST_AVAIL, self.avail(r));
        put_u64(&mut raw, ST_AVAIL_MAX, r.avail_max.max(self.avail(r)));
        r.avail_max = 0;
        // The audio timestamp: the frames played, as time (the default
        // type, from the DMA position).
        put_u32(&mut raw, ST_AUDIO_TSTAMP_DATA, audio_data & 0x1);
        if let Some(s) = r.setup {
            let frames = r.hw_ptr();
            ns(frames * 1_000_000_000 / u64::from(s.rate), &mut raw, ST_AUDIO_TSTAMP);
        }
        drop(g);
        copy_to_user(arg, &raw).map_err(|_| EFAULT)?;
        Ok(0)
    }

    fn sync_ptr(&self, arg: u64) -> Result<u64> {
        let mut raw = [0u8; SYNC_PTR_SIZE];
        copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
        let flags = get_u32(&raw, SP_FLAGS);
        let mut g = self.run.lock();
        let r = g.as_mut().ok_or(EBADFD)?;
        if flags & SYNC_PTR_HWSYNC != 0 {
            self.update(r);
        }
        if flags & SYNC_PTR_APPL == 0 {
            let appl = get_u64(&raw, SP_CONTROL + MC_APPL_PTR);
            if r.setup.is_some() && appl < r.sw.boundary {
                r.set_appl(appl);
            }
        }
        if flags & SYNC_PTR_AVAIL_MIN == 0 {
            r.control.write_u64(MC_AVAIL_MIN, get_u64(&raw, SP_CONTROL + MC_AVAIL_MIN));
        }
        let mut status = [0u8; MMAP_STATUS_SIZE];
        r.status.read(0, &mut status);
        raw[SP_STATUS..SP_STATUS + MMAP_STATUS_SIZE].copy_from_slice(&status);
        put_u64(&mut raw, SP_CONTROL + MC_APPL_PTR, r.appl());
        put_u64(&mut raw, SP_CONTROL + MC_AVAIL_MIN, r.avail_min());
        drop(g);
        // The program's new position may let waiters go.
        self.notify();
        copy_to_user(arg, &raw).map_err(|_| EFAULT)?;
        Ok(0)
    }

    /// `struct snd_pcm_info` for this stream.
    pub(super) fn info(&self, card: &super::Card) -> [u8; PCM_INFO_SIZE] {
        let mut b = [0u8; PCM_INFO_SIZE];
        let pcm = card.pcms.iter().find(|p| p.device == self.device);
        put_u32(&mut b, PI_DEVICE, self.device);
        put_u32(&mut b, PI_SUBDEVICE, 0);
        put_u32(&mut b, PI_STREAM, self.dir);
        put_u32(&mut b, PI_CARD, card.index);
        put_str(&mut b, PI_ID, 64, pcm.map_or("", |p| p.id.as_str()));
        put_str(&mut b, PI_NAME, 80, pcm.map_or("", |p| p.name.as_str()));
        put_str(&mut b, PI_SUBNAME, 32, "subdevice #0");
        put_u32(&mut b, PI_DEV_CLASS, PCM_CLASS_GENERIC);
        put_u32(&mut b, PI_DEV_SUBCLASS, PCM_SUBCLASS_GENERIC_MIX);
        put_u32(&mut b, PI_SUBDEVICES_COUNT, 1);
        put_u32(&mut b, PI_SUBDEVICES_AVAIL, u32::from(!self.opened.load(Ordering::Acquire)));
        b
    }

    pub(super) fn proc_info(&self, card: &super::Card, p: &super::Pcm) -> String {
        format!(
            "card: {}\ndevice: {}\nsubdevice: 0\nstream: {}\nid: {}\nname: {}\nsubname: subdevice #0\nclass: 0\nsubclass: 0\nsubdevices_count: 1\nsubdevices_avail: {}\n",
            card.index,
            p.device,
            if self.playback() { "PLAYBACK" } else { "CAPTURE" },
            p.id,
            p.name,
            u32::from(!self.opened.load(Ordering::Acquire))
        )
    }

    pub(super) fn proc_status(&self) -> String {
        let mut g = self.run.lock();
        let Some(r) = g.as_mut() else { return String::from("closed\n") };
        self.update(r);
        let state = ["OPEN", "SETUP", "PREPARED", "RUNNING", "XRUN", "DRAINING", "PAUSED", "SUSPENDED", "DISCONNECTED"]
            .get(r.state as usize)
            .copied()
            .unwrap_or("?");
        let mut s = format!("state: {state}\nowner_pid   : 0\n");
        let _ = write!(
            s,
            "trigger_time: {}.{:09}\navail       : {}\navail_max   : {}\n-----\nhw_ptr      : {}\nappl_ptr    : {}\n",
            r.trigger_ns / 1_000_000_000,
            r.trigger_ns % 1_000_000_000,
            self.avail(r),
            r.avail_max,
            r.hw_ptr(),
            r.appl()
        );
        s
    }

    pub(super) fn proc_hw_params(&self) -> String {
        let g = self.run.lock();
        let Some(s) = g.as_ref().and_then(|r| r.setup) else { return String::from("closed\n") };
        format!(
            "access: {}\nformat: {}\nsubformat: STD\nchannels: {}\nrate: {} ({}/1)\nperiod_size: {}\nbuffer_size: {}\n",
            if s.access == ACCESS_MMAP_INTERLEAVED { "MMAP_INTERLEAVED" } else { "RW_INTERLEAVED" },
            s.format,
            s.channels,
            s.rate,
            s.rate,
            s.period_size,
            s.buffer_size
        )
    }

    pub(super) fn proc_sw_params(&self) -> String {
        let g = self.run.lock();
        let Some(r) = g.as_ref().filter(|r| r.setup.is_some()) else { return String::from("closed\n") };
        format!(
            "tstamp_mode: {}\nperiod_step: {}\navail_min: {}\nstart_threshold: {}\nstop_threshold: {}\nsilence_threshold: {}\nsilence_size: {}\nboundary: {}\n",
            if r.sw.tstamp_mode == 0 { "NONE" } else { "ENABLE" },
            r.sw.period_step,
            r.avail_min(),
            r.sw.start_threshold,
            r.sw.stop_threshold,
            r.sw.silence_threshold,
            r.sw.silence_size,
            r.sw.boundary
        )
    }
}

/// Open the stream (one opener at a time).
pub fn open(s: Arc<Substream>, flags: u32) -> Result<Arc<dyn File>> {
    if s.gone.load(Ordering::Acquire) {
        return Err(ENODEV);
    }
    if s.opened.swap(true, Ordering::AcqRel) {
        return Err(EBUSY);
    }
    let pages = Pages::new(PAGE_SIZE as usize).and_then(|st| Ok((st, Pages::new(PAGE_SIZE as usize)?)));
    let (status, control) = match pages {
        Ok(p) => p,
        Err(e) => {
            s.opened.store(false, Ordering::Release);
            return Err(e);
        }
    };
    let sw = Sw {
        tstamp_mode: 0,
        period_step: 1,
        start_threshold: 1,
        stop_threshold: 0,
        silence_threshold: 0,
        silence_size: 0,
        boundary: 1,
        tstamp_type: TSTAMP_TYPE_GETTIMEOFDAY,
    };
    *s.run.lock() = Some(Run {
        state: STATE_OPEN,
        setup: None,
        buf: None,
        status,
        control,
        sw,
        hw_base: 0,
        last_pos: 0,
        avail_max: 0,
        trigger_ns: 0,
        silenced_to: 0,
        user_pversion: 0,
    });
    Ok(Arc::new(PcmFile { s, flags: AtomicU32::new(flags) }))
}

struct PcmFile {
    s: Arc<Substream>,
    flags: AtomicU32,
}

impl Drop for PcmFile {
    fn drop(&mut self) {
        let s = &self.s;
        {
            let mut g = s.run.lock();
            if let Some(r) = g.as_ref()
                && matches!(r.state, STATE_RUNNING | STATE_DRAINING | STATE_PAUSED)
            {
                s.ops.stop();
            }
            s.ops.release();
            *g = None;
        }
        s.opened.store(false, Ordering::Release);
        s.notify();
    }
}

impl PcmFile {
    fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    /// `WRITEI_FRAMES`/`READI_FRAMES`: `struct snd_xferi` (result, buf,
    /// frames); the result is written back.
    fn xfer(&self, arg: u64, write: bool) -> Result<u64> {
        let mut raw = [0u8; XFERI_SIZE];
        copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
        let (buf, frames) = (get_u64(&raw, 8), get_u64(&raw, 16));
        if (write && !self.s.playback()) || (!write && self.s.playback()) {
            return Err(EINVAL);
        }
        let r = if write {
            self.s.write_frames(buf, frames, self.nonblock())
        } else {
            self.s.read_frames(buf, frames, self.nonblock())
        };
        let n = r?;
        write_user(arg, &(n as i64)).map_err(|_| EFAULT)?;
        Ok(0)
    }
}

impl File for PcmFile {
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        let s = &self.s;
        if s.gone.load(Ordering::Acquire) && cmd != PCM_IOCTL_PVERSION {
            return Err(ENODEV);
        }
        match cmd {
            PCM_IOCTL_PVERSION => write_user(arg, &PCM_VERSION).map(|_| 0).map_err(|_| EFAULT),
            PCM_IOCTL_INFO => {
                let card = super::card(s.card.load(Ordering::Relaxed)).ok_or(ENODEV)?;
                copy_to_user(arg, &s.info(&card)).map(|_| 0).map_err(|_| EFAULT)
            }
            PCM_IOCTL_USER_PVERSION => {
                let v: u32 = read_user(arg).map_err(|_| EFAULT)?;
                if let Some(r) = s.run.lock().as_mut() {
                    r.user_pversion = v;
                }
                Ok(0)
            }
            PCM_IOCTL_TSTAMP => Ok(0),
            PCM_IOCTL_TTSTAMP => {
                let t: u32 = read_user(arg).map_err(|_| EFAULT)?;
                if t > TSTAMP_TYPE_MONOTONIC_RAW {
                    return Err(EINVAL);
                }
                if let Some(r) = s.run.lock().as_mut() {
                    r.sw.tstamp_type = t;
                }
                Ok(0)
            }
            PCM_IOCTL_HW_REFINE => s.hw_params(arg, false),
            PCM_IOCTL_HW_PARAMS => s.hw_params(arg, true),
            PCM_IOCTL_HW_FREE => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                if matches!(r.state, STATE_RUNNING | STATE_DRAINING | STATE_PAUSED) {
                    return Err(EBADFD);
                }
                s.ops.release();
                r.setup = None;
                r.buf = None;
                r.set_state(STATE_OPEN);
                Ok(0)
            }
            PCM_IOCTL_SW_PARAMS => s.sw_params(arg),
            PCM_IOCTL_STATUS => s.status(arg, false),
            PCM_IOCTL_STATUS_EXT => s.status(arg, true),
            PCM_IOCTL_DELAY => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                s.update(r);
                if r.state == STATE_XRUN {
                    return Err(EPIPE);
                }
                let d = s.queued(r) as i64;
                drop(g);
                write_user(arg, &d).map(|_| 0).map_err(|_| EFAULT)
            }
            PCM_IOCTL_HWSYNC => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                s.update(r);
                if r.state == STATE_XRUN { Err(EPIPE) } else { Ok(0) }
            }
            PCM_IOCTL_SYNC_PTR => s.sync_ptr(arg),
            PCM_IOCTL_CHANNEL_INFO => {
                let mut raw = [0u8; CHANNEL_INFO_SIZE];
                copy_from_user(&mut raw, arg).map_err(|_| EFAULT)?;
                let ch = get_u32(&raw, 0);
                let setup = s.run.lock().as_ref().and_then(|r| r.setup).ok_or(EBADFD)?;
                if ch >= setup.channels {
                    return Err(EINVAL);
                }
                put_u64(&mut raw, 8, MMAP_OFFSET_DATA);
                put_u32(&mut raw, 16, ch * setup.sample_bits);
                put_u32(&mut raw, 20, setup.sample_bits * setup.channels);
                copy_to_user(arg, &raw).map(|_| 0).map_err(|_| EFAULT)
            }
            PCM_IOCTL_PREPARE => s.prepare(),
            PCM_IOCTL_RESET => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                if !matches!(r.state, STATE_PREPARED | STATE_RUNNING | STATE_PAUSED) {
                    return Err(EBADFD);
                }
                s.update(r);
                let hw = r.hw_ptr();
                r.set_appl(hw);
                Ok(0)
            }
            PCM_IOCTL_START => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                s.start_locked(r)?;
                drop(g);
                s.notify();
                Ok(0)
            }
            PCM_IOCTL_DROP => s.drop_stream(),
            PCM_IOCTL_DRAIN => s.drain(self.nonblock()),
            PCM_IOCTL_PAUSE => {
                let on: i32 = read_user(arg).map_err(|_| EFAULT)?;
                s.pause(on != 0)
            }
            PCM_IOCTL_REWIND => s.move_appl(arg, true),
            PCM_IOCTL_FORWARD => s.move_appl(arg, false),
            PCM_IOCTL_RESUME => Err(ENOSYS_PCM),
            PCM_IOCTL_XRUN => {
                let mut g = s.run.lock();
                let r = g.as_mut().ok_or(EBADFD)?;
                match r.state {
                    STATE_XRUN => Ok(0),
                    STATE_PREPARED | STATE_RUNNING | STATE_PAUSED | STATE_DRAINING => {
                        s.xrun(r);
                        drop(g);
                        s.notify();
                        Ok(0)
                    }
                    _ => Err(EBADFD),
                }
            }
            PCM_IOCTL_WRITEI_FRAMES => self.xfer(arg, true),
            PCM_IOCTL_READI_FRAMES => self.xfer(arg, false),
            _ => super::unknown_ioctl("PCM", cmd),
        }
    }

    fn poll(&self) -> u16 {
        let s = &self.s;
        let dir = if s.playback() { POLLOUT } else { POLLIN };
        if s.gone.load(Ordering::Acquire) {
            return dir | POLLERR;
        }
        let g = s.run.lock();
        let Some(r) = g.as_ref() else { return POLLERR };
        match r.state {
            STATE_RUNNING | STATE_PREPARED | STATE_PAUSED => {
                if s.avail(r) >= r.avail_min() {
                    dir
                } else {
                    0
                }
            }
            STATE_DRAINING if !s.playback() => dir,
            STATE_DRAINING => 0,
            _ => dir | POLLERR,
        }
    }

    fn event_count(&self) -> u64 {
        self.s.events.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        let card = self.s.card.load(Ordering::Relaxed);
        let base = if self.s.playback() { MINOR_PLAYBACK } else { MINOR_CAPTURE };
        let rdev = vfs::makedev(SOUND_MAJOR, card * MINORS_PER_CARD + base + self.s.device);
        Ok(Metadata { mode: vfs::S_IFCHR | 0o660, rdev, nlink: 1, ..Metadata::default() })
    }

    /// The buffer at 0, the status page at 0x80000000 (or 0x82000000) and
    /// the control page at 0x81000000 (or 0x83000000).
    fn mmap_source(&self, offset: u64) -> Option<Result<Arc<dyn Inode>>> {
        let g = self.s.run.lock();
        let Some(r) = g.as_ref() else { return Some(Err(EBADFD)) };
        let pages = match offset & !0x00ff_ffff {
            MMAP_OFFSET_STATUS_OLD | MMAP_OFFSET_STATUS_NEW => Some(r.status.clone()),
            MMAP_OFFSET_CONTROL_OLD | MMAP_OFFSET_CONTROL_NEW => Some(r.control.clone()),
            MMAP_OFFSET_DATA => r.buf.clone(),
            _ => None,
        };
        Some(pages.map(|p| Arc::new(MapSource(p)) as Arc<dyn Inode>).ok_or(EINVAL))
    }
}

/// RESUME: Slate doesn't suspend streams (ENOSYS, as Linux gives for
/// hardware that can't resume; alsa-lib then prepares again).
const ENOSYS_PCM: crate::abi::linux::errno::Errno = crate::abi::linux::errno::ENOSYS;
