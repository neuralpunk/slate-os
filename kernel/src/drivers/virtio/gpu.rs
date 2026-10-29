// SPDX-License-Identifier: MIT OR Apache-2.0

//! virtio-gpu, 2D (VIRTIO 1.2 §5.7), as a DRM display (ADR 0033, ADR
//! 0100).
//!
//! Each of the device's scanouts is an output of the card, with the size
//! the host gives it (and the usual smaller modes), and the host's EDID
//! when it offers one (VIRTIO_GPU_F_EDID). Every framebuffer a client
//! shows becomes a host resource whose backing is the dumb buffer's own
//! pages; showing one transfers it to the host, points the scanout at it
//! and flushes. The cursor plane is the device's cursor queue: a 64 × 64
//! resource per scanout, updated and moved there. When the host changes
//! its displays (a window resized, a display enabled or disabled), the
//! configuration interrupt brings a display event: the scanouts are read
//! again and the card announces a hotplug.
//!
//! When virtio-gpu is the machine's only display adapter, it also carries
//! the console on scanout 0: a resource backed by the firmware framebuffer
//! the console draws into, flushed by a kernel thread as the console
//! changes, shown whenever no DRM master is.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::{Transport, Virtqueue};
use crate::drivers::drm::{
    self, CONNECTOR_VIRTUAL, CURSOR_SIZE, CursorImage, Display, FORMAT_ARGB8888, Framebuffer, OutputInfo,
};
use crate::drivers::pci::Device;
use crate::mm::{PAGE_SIZE, PhysAddr};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// Feature bits (§5.7.3).
const F_EDID: u64 = 1 << 1;
// Configuration (§5.7.4): events_read, events_clear, num_scanouts.
const CFG_EVENTS_READ: usize = 0;
const CFG_EVENTS_CLEAR: usize = 4;
const CFG_NUM_SCANOUTS: usize = 8;
/// VIRTIO_GPU_EVENT_DISPLAY: the host's displays changed.
const EVENT_DISPLAY: u32 = 1;

// Control commands and responses (§5.7.6.7).
const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_GET_EDID: u32 = 0x010a;
// Cursor commands (§5.7.6.10).
const CMD_UPDATE_CURSOR: u32 = 0x0300;
const CMD_MOVE_CURSOR: u32 = 0x0301;
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_OK_EDID: u32 = 0x1104;
/// Pixel formats (§5.7.6.8): B8G8R8X8 is XRGB8888's byte order in memory.
const FORMAT_B8G8R8A8_UNORM: u32 = 1;
const FORMAT_B8G8R8X8_UNORM: u32 = 2;
/// Most scanouts a device reports (§5.7.6.8, VIRTIO_GPU_MAX_SCANOUTS).
const MAX_SCANOUTS: usize = 16;
/// Smaller modes offered besides the host's size.
const MODES: [(u32, u32); 12] = [
    (2560, 1440),
    (1920, 1200),
    (1920, 1080),
    (1680, 1050),
    (1600, 900),
    (1440, 900),
    (1366, 768),
    (1280, 1024),
    (1280, 800),
    (1280, 720),
    (1024, 768),
    (800, 600),
];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Header {
    kind: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
    padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DisplayOne {
    r: Rect,
    enabled: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DisplayInfo {
    hdr: Header,
    pmodes: [DisplayOne; MAX_SCANOUTS],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetEdid {
    hdr: Header,
    scanout: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RespEdid {
    hdr: Header,
    size: u32,
    padding: u32,
    edid: [u8; 1024],
}

impl Default for RespEdid {
    fn default() -> RespEdid {
        RespEdid { hdr: Header::default(), size: 0, padding: 0, edid: [0; 1024] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Create2d {
    hdr: Header,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Unref {
    hdr: Header,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SetScanout {
    hdr: Header,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Flush {
    hdr: Header,
    r: Rect,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Transfer {
    hdr: Header,
    r: Rect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AttachBacking {
    hdr: Header,
    resource_id: u32,
    nr_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

/// `struct virtio_gpu_cursor_pos` and `virtio_gpu_update_cursor`
/// (§5.7.6.10): MOVE_CURSOR uses only the position.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UpdateCursor {
    hdr: Header,
    scanout_id: u32,
    x: u32,
    y: u32,
    pos_padding: u32,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    padding: u32,
}

/// A host resource standing for one framebuffer.
struct Resource {
    id: u32,
    /// Keeps the backing pages alive while the host may read them.
    _buffer: Arc<drm::Buffer>,
    width: u32,
    height: u32,
    offset: u32,
}

/// The console's resource: the firmware framebuffer's pages.
struct Console {
    id: u32,
    width: u32,
    height: u32,
    pitch: u32,
}

/// A scanout as the host describes it.
#[derive(Clone, Default)]
struct Scanout {
    enabled: bool,
    width: u32,
    height: u32,
    edid: Option<Vec<u8>>,
}

/// A scanout's cursor: its resource and pages, and the hotspot shown.
struct CursorRes {
    id: u32,
    frames: Vec<PhysAddr>,
    hot: (i32, i32),
}

pub struct VirtioGpu {
    _transport: Transport,
    queue: Virtqueue,
    cursor_queue: Option<Virtqueue>,
    edid: bool,
    /// The card's number, once registered.
    minor: AtomicU32,
    scanouts: IrqSpinLock<Vec<Scanout>>,
    next_id: AtomicU32,
    /// Framebuffer id → its resource.
    resources: IrqSpinLock<BTreeMap<u32, Resource>>,
    cursors: IrqSpinLock<BTreeMap<usize, CursorRes>>,
    console: Option<Console>,
    /// The console is on screen (no master has a picture up).
    console_shown: AtomicBool,
    /// Rows the console redrew since the last flush (min, max+1), packed.
    damage: AtomicU64,
    damage_wake: WaitQueue,
    /// The configuration interrupt came (a display event, perhaps).
    config_changed: AtomicBool,
    config_wake: WaitQueue,
}

/// The virtio-gpu that carries the console, for its damage reports.
static CONSOLE_GPU: slate_sync::Once<Arc<VirtioGpu>> = slate_sync::Once::new();

fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: T is a plain #[repr(C)] structure of integers.
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>()) }
}

impl VirtioGpu {
    /// Send a command (`req`, with `extra` bytes appended) and read the
    /// response into `resp`; false on an error response.
    fn command<Q: Copy, R: Copy + Default>(&self, req: &Q, extra: &[u8], resp: &mut R) -> bool {
        let mut buf = Vec::with_capacity(size_of::<Q>() + extra.len());
        buf.extend_from_slice(bytes_of(req));
        buf.extend_from_slice(extra);
        let mut out = Box::new(R::default());
        let mut segs = Vec::new();
        super::segments(buf.as_ptr(), buf.len(), false, &mut segs);
        super::segments(&mut *out as *mut R as *const u8, size_of::<R>(), true, &mut segs);
        self.queue.submit_and_wait(&segs);
        // SAFETY: The device wrote the response before returning the chain.
        *resp = unsafe { core::ptr::read_volatile(&*out) };
        // SAFETY: Every response starts with a Header.
        let kind = unsafe { (*(resp as *const R as *const Header)).kind };
        matches!(kind, RESP_OK_NODATA | RESP_OK_DISPLAY_INFO | RESP_OK_EDID)
    }

    fn simple<Q: Copy>(&self, req: &Q) -> bool {
        let mut h = Header::default();
        self.command(req, &[], &mut h)
    }

    fn hdr(kind: u32) -> Header {
        Header { kind, ..Header::default() }
    }

    /// A command on the cursor queue (no response, §5.7.6.10).
    fn cursor_command(&self, c: &UpdateCursor) {
        let Some(q) = &self.cursor_queue else { return };
        let buf = Box::new(*c);
        let mut segs = Vec::new();
        super::segments(&*buf as *const UpdateCursor as *const u8, size_of::<UpdateCursor>(), false, &mut segs);
        q.submit_and_wait(&segs);
    }

    /// A resource of `width` × `height` pixels backed by `pages` (physical
    /// address and length of each piece).
    fn create(&self, width: u32, height: u32, format: u32, pages: &[(u64, u32)]) -> Option<u32> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let c = Create2d { hdr: Self::hdr(CMD_RESOURCE_CREATE_2D), resource_id: id, format, width, height };
        if !self.simple(&c) {
            return None;
        }
        let mut entries = Vec::with_capacity(pages.len() * size_of::<MemEntry>());
        for &(addr, length) in pages {
            entries.extend_from_slice(bytes_of(&MemEntry { addr, length, padding: 0 }));
        }
        let a = AttachBacking {
            hdr: Self::hdr(CMD_RESOURCE_ATTACH_BACKING),
            resource_id: id,
            nr_entries: pages.len() as u32,
        };
        let mut h = Header::default();
        if !self.command(&a, &entries, &mut h) {
            self.unref(id);
            return None;
        }
        Some(id)
    }

    fn unref(&self, id: u32) {
        self.simple(&Unref { hdr: Self::hdr(CMD_RESOURCE_UNREF), resource_id: id, padding: 0 });
    }

    /// Copy rows `y0..y1` of resource `id` to the host and show them.
    fn update(&self, id: u32, width: u32, y0: u32, y1: u32, offset: u64, pitch: u32) {
        self.update_rect(id, 0..width, y0..y1, offset, pitch);
    }

    /// Copy the rectangle `cols` × `rows` of resource `id` to the host and
    /// show it. The transfer's offset is where the rectangle starts in the
    /// backing; the host steps through it a resource row (`pitch`) at a
    /// time (virtio spec §5.7.6.8, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D).
    fn update_rect(&self, id: u32, cols: core::ops::Range<u32>, rows: core::ops::Range<u32>, offset: u64, pitch: u32) {
        let r = Rect { x: cols.start, y: rows.start, width: cols.end - cols.start, height: rows.end - rows.start };
        let t = Transfer {
            hdr: Self::hdr(CMD_TRANSFER_TO_HOST_2D),
            r,
            offset: offset + u64::from(rows.start) * u64::from(pitch) + u64::from(cols.start) * 4,
            resource_id: id,
            padding: 0,
        };
        self.simple(&t);
        self.simple(&Flush { hdr: Self::hdr(CMD_RESOURCE_FLUSH), r, resource_id: id, padding: 0 });
    }

    /// Point scanout `out` at resource `id` (0: nothing), `width` × `height`.
    fn scanout(&self, out: usize, id: u32, width: u32, height: u32) {
        let s = SetScanout {
            hdr: Self::hdr(CMD_SET_SCANOUT),
            r: Rect { x: 0, y: 0, width, height },
            scanout_id: out as u32,
            resource_id: id,
        };
        self.simple(&s);
    }

    fn show_console(&self) {
        if let Some(c) = &self.console {
            self.console_shown.store(true, Ordering::Release);
            self.scanout(0, c.id, c.width, c.height);
            self.update(c.id, c.width, 0, c.height, 0, c.pitch);
        }
    }

    /// The console thread: flush what the console drew.
    fn flush_console(&self) -> ! {
        loop {
            self.damage_wake.wait_until(|| self.damage.load(Ordering::Acquire) != 0);
            let d = self.damage.swap(0, Ordering::AcqRel);
            if let Some(c) = &self.console
                && self.console_shown.load(Ordering::Acquire)
            {
                let (y0, y1) = ((d >> 32) as u32, (d & 0xffff_ffff) as u32);
                let (y0, y1) = (y0.min(c.height), y1.min(c.height));
                if y1 > y0 {
                    self.update(c.id, c.width, y0, y1, 0, c.pitch);
                }
            }
        }
    }

    /// Read the host's scanouts (and their EDIDs).
    fn read_scanouts(&self) -> Vec<Scanout> {
        let n = self.scanouts.lock().len();
        let mut info = DisplayInfo::default();
        if !self.command(&VirtioGpu::hdr(CMD_GET_DISPLAY_INFO), &[], &mut info) {
            return self.scanouts.lock().clone();
        }
        (0..n)
            .map(|i| {
                let p = info.pmodes[i];
                let edid = self.edid.then(|| {
                    let mut r = RespEdid::default();
                    let q = GetEdid { hdr: Self::hdr(CMD_GET_EDID), scanout: i as u32, padding: 0 };
                    if !self.command(&q, &[], &mut r) {
                        return None;
                    }
                    // The block and its extensions (the host may pad it).
                    let size = (r.size as usize).min(1024);
                    let len = if size >= 128 { (128 * (1 + usize::from(r.edid[126]))).min(size) } else { size };
                    (len > 0).then(|| r.edid[..len].to_vec())
                });
                Scanout {
                    enabled: p.enabled != 0 && p.r.width > 0,
                    width: p.r.width,
                    height: p.r.height,
                    edid: edid.flatten(),
                }
            })
            .collect()
    }

    /// The display-event thread: on a configuration interrupt, read the
    /// events, and on a display event the scanouts again.
    fn display_events(&self) -> ! {
        loop {
            self.config_wake.wait_until(|| self.config_changed.load(Ordering::Acquire));
            self.config_changed.store(false, Ordering::Release);
            let events = self._transport.config(|r| r(CFG_EVENTS_READ));
            if events & EVENT_DISPLAY == 0 {
                continue;
            }
            self._transport.config_w32(CFG_EVENTS_CLEAR, EVENT_DISPLAY);
            let new = self.read_scanouts();
            let summary: Vec<alloc::string::String> = new
                .iter()
                .map(|s| if s.enabled { alloc::format!("{}x{}", s.width, s.height) } else { "off".into() })
                .collect();
            log_info!("virtio-gpu: displays now {}", summary.join(", "));
            *self.scanouts.lock() = new;
            drm::hotplug(self.minor.load(Ordering::Relaxed));
        }
    }

    /// Scanout `out`'s cursor resource, made on first use.
    fn cursor_resource(&self, out: usize) -> Option<u32> {
        if let Some(c) = self.cursors.lock().get(&out) {
            return Some(c.id);
        }
        let pages = (CURSOR_SIZE * CURSOR_SIZE * 4).div_ceil(PAGE_SIZE as u32);
        let mut frames = Vec::new();
        for _ in 0..pages {
            frames.push(crate::mm::frame::alloc_zeroed()?);
        }
        let backing: Vec<(u64, u32)> = frames.iter().map(|f| (f.0, PAGE_SIZE as u32)).collect();
        let id = self.create(CURSOR_SIZE, CURSOR_SIZE, FORMAT_B8G8R8A8_UNORM, &backing)?;
        self.cursors.lock().insert(out, CursorRes { id, frames, hot: (0, 0) });
        Some(id)
    }
}

impl Display for Arc<VirtioGpu> {
    fn driver(&self) -> &'static str {
        "virtio_gpu"
    }
    fn description(&self) -> &'static str {
        "virtio GPU"
    }
    fn outputs(&self) -> usize {
        self.scanouts.lock().len()
    }
    fn output(&self, out: usize) -> OutputInfo {
        let Some(s) = self.scanouts.lock().get(out).cloned() else { return OutputInfo::default() };
        if !s.enabled {
            return OutputInfo { edid: s.edid, ..OutputInfo::default() };
        }
        let mut modes = alloc::vec![(s.width, s.height, 60)];
        modes.extend(
            MODES
                .iter()
                .filter(|&&(w, h)| w <= s.width && h <= s.height && (w, h) != (s.width, s.height))
                .map(|&(w, h)| (w, h, 60)),
        );
        let size_mm = s.edid.as_deref().and_then(slate_edid::parse).map_or((0, 0), |p| p.size_mm);
        OutputInfo { connected: true, modes, size_mm, edid: s.edid }
    }
    fn connector_type(&self) -> u32 {
        CONNECTOR_VIRTUAL
    }
    fn present(&self, out: usize, fb: &Arc<Framebuffer>, mode: (u32, u32)) {
        if out == 0 {
            self.console_shown.store(false, Ordering::Release);
        }
        let mut res = self.resources.lock();
        if !res.contains_key(&fb.id) {
            // The host reads rows `pitch` apart: make the resource that
            // wide, and show only the framebuffer's part.
            let width = fb.pitch / 4;
            let format = if fb.format == FORMAT_ARGB8888 { FORMAT_B8G8R8A8_UNORM } else { FORMAT_B8G8R8X8_UNORM };
            let pages: Vec<(u64, u32)> = fb.buffer.frames().iter().map(|f| (f.0, PAGE_SIZE as u32)).collect();
            let height = fb.height + fb.offset.div_ceil(fb.pitch);
            drop(res);
            let Some(id) = self.create(width, height, format, &pages) else {
                log_warn!("virtio-gpu: could not create a {width}x{height} resource");
                return;
            };
            res = self.resources.lock();
            res.insert(
                fb.id,
                Resource { id, _buffer: fb.buffer.clone(), width: fb.width, height: fb.height, offset: fb.offset },
            );
        }
        let r = &res[&fb.id];
        let (id, w, h, off) = (r.id, r.width, r.height, r.offset);
        drop(res);
        self.update(id, w, 0, h, u64::from(off), fb.pitch);
        self.scanout(out, id, mode.0.min(w), mode.1.min(h));
    }
    fn present_rect(
        &self,
        out: usize,
        fb: &Arc<Framebuffer>,
        cols: core::ops::Range<u32>,
        rows: core::ops::Range<u32>,
    ) {
        // Only the rectangle that changed goes to the host (ADR 0039, ADR
        // 0066), once the framebuffer has its resource and is on the
        // screen.
        let known = self.resources.lock().get(&fb.id).map(|r| (r.id, r.width, r.height, r.offset));
        match known {
            Some((id, w, h, off)) if out != 0 || !self.console_shown.load(Ordering::Acquire) => {
                let (y0, y1) = (rows.start.min(h), rows.end.min(h));
                let (x0, x1) = (cols.start.min(w), cols.end.min(w));
                if y1 > y0 && x1 > x0 {
                    self.update_rect(id, x0..x1, y0..y1, u64::from(off), fb.pitch);
                }
            }
            _ => self.present(out, fb, (fb.width, fb.height)),
        }
    }
    fn blank(&self, out: usize) {
        if out == 0 {
            self.console_shown.store(false, Ordering::Release);
        }
        self.scanout(out, 0, 0, 0);
    }
    fn cursor(&self, out: usize, image: Option<CursorImage>) {
        let Some(img) = image else {
            let c =
                UpdateCursor { hdr: VirtioGpu::hdr(CMD_UPDATE_CURSOR), scanout_id: out as u32, ..Default::default() };
            self.cursor_command(&c);
            return;
        };
        let Some(id) = self.cursor_resource(out) else { return };
        // The image into the resource's pages, 64 pixels a row, the rest
        // transparent.
        {
            let mut cursors = self.cursors.lock();
            let Some(c) = cursors.get_mut(&out) else { return };
            c.hot = img.hot;
            for (k, f) in c.frames.iter().enumerate() {
                let page = f.to_virt() as *mut u32;
                for i in 0..PAGE_SIZE as usize / 4 {
                    let at = k * PAGE_SIZE as usize / 4 + i;
                    let (x, y) = ((at % CURSOR_SIZE as usize) as u32, (at / CURSOR_SIZE as usize) as u32);
                    let p = if x < img.width && y < img.height { img.pixels[(y * img.width + x) as usize] } else { 0 };
                    // SAFETY: The frame is ours and in the direct map; `i`
                    // stays within its page.
                    unsafe { page.add(i).write_volatile(p) };
                }
            }
        }
        let t = Transfer {
            hdr: VirtioGpu::hdr(CMD_TRANSFER_TO_HOST_2D),
            r: Rect { x: 0, y: 0, width: CURSOR_SIZE, height: CURSOR_SIZE },
            offset: 0,
            resource_id: id,
            padding: 0,
        };
        self.simple(&t);
        let c = UpdateCursor {
            hdr: VirtioGpu::hdr(CMD_UPDATE_CURSOR),
            scanout_id: out as u32,
            resource_id: id,
            hot_x: img.hot.0.max(0) as u32,
            hot_y: img.hot.1.max(0) as u32,
            ..Default::default()
        };
        self.cursor_command(&c);
    }
    fn move_cursor(&self, out: usize, x: i32, y: i32) {
        // The host places the hotspot.
        let hot = self.cursors.lock().get(&out).map_or((0, 0), |c| c.hot);
        let c = UpdateCursor {
            hdr: VirtioGpu::hdr(CMD_MOVE_CURSOR),
            scanout_id: out as u32,
            x: (x + hot.0).max(0) as u32,
            y: (y + hot.1).max(0) as u32,
            ..Default::default()
        };
        self.cursor_command(&c);
    }
    fn forget(&self, fb: u32) {
        if let Some(r) = self.resources.lock().remove(&fb) {
            self.unref(r.id);
        }
    }
    fn release(&self) {
        // Resources go with their framebuffers; the cursors hide; the
        // other scanouts go dark and the console comes back.
        let gone: Vec<u32> = core::mem::take(&mut *self.resources.lock()).into_values().map(|r| r.id).collect();
        let n = self.scanouts.lock().len();
        for out in 0..n {
            Display::cursor(self, out, None);
            if out > 0 {
                self.scanout(out, 0, 0, 0);
            }
        }
        for id in gone {
            self.unref(id);
        }
        crate::drivers::fbcon::set_suspended(false);
        self.show_console();
    }
}

/// The console redrew rows `y0..y1` (pixels): flush them soon.
pub fn console_damage(y0: u32, y1: u32) {
    let Some(g) = CONSOLE_GPU.get() else { return };
    let mut cur = g.damage.load(Ordering::Relaxed);
    loop {
        let (a, b) = if cur == 0 { (y0, y1) } else { (((cur >> 32) as u32).min(y0), (cur as u32).max(y1)) };
        let new = (u64::from(a) << 32) | u64::from(b.max(1));
        match g.damage.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => cur = x,
        }
    }
    g.damage_wake.wake_all();
}

/// Start the console on a framebuffer in RAM, `width` × `height`.
fn console_in_ram(width: u32, height: u32) {
    let pages = (u64::from(width) * u64::from(height) * 4).div_ceil(PAGE_SIZE);
    let mut frames = Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        match crate::mm::frame::alloc_zeroed() {
            Some(f) => frames.push(f),
            None => {
                log_warn!("virtio-gpu: no memory for a console framebuffer");
                return;
            }
        }
    }
    let addr = crate::mm::vmap::map_ram(&frames) as u64;
    let fb = crate::arch::boot::Framebuffer {
        addr,
        width: width as usize,
        height: height as usize,
        pitch: width as usize * 4,
        bpp: 32,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };
    crate::drivers::fbcon::init(fb);
}

/// Whether some other display adapter (PCI class 03h) is present: then the
/// firmware framebuffer is that adapter's, not ours.
fn other_display_adapter() -> bool {
    crate::drivers::pci::devices().iter().any(|d| d.class == 0x03 && super::device_type(d).is_none())
}

/// Bring up one virtio-gpu device as a DRM card.
pub fn probe(pci: Arc<Device>) -> Option<()> {
    let transport = Transport::new(pci)?;
    let features = transport.init(F_EDID)?;
    // MSI-X: one vector for the control queue, so a command's sender
    // sleeps until the host has done it (polling where it can't sleep, or
    // without MSI-X), as virtio-blk does; one for configuration changes
    // (display events). The cursor queue is polled.
    let slot: Arc<slate_sync::Once<Arc<VirtioGpu>>> = Arc::new(slate_sync::Once::new());
    let irq_slot = slot.clone();
    let vector = crate::arch::irq::alloc_vector(
        "virtio-gpu",
        Box::new(move || {
            if let Some(g) = irq_slot.get() {
                g.queue.interrupt();
            }
        }),
    );
    let cfg_slot = slot.clone();
    let config_vector = crate::arch::irq::alloc_vector(
        "virtio-gpu-config",
        Box::new(move || {
            if let Some(g) = cfg_slot.get() {
                g.config_changed.store(true, Ordering::Release);
                g.config_wake.wake_all();
            }
        }),
    );
    let msix = match (vector, config_vector) {
        (Some(v), Some(c)) => transport.pci.enable_msix(&[v, c], crate::arch::irq::device_irq_target()),
        _ => None,
    };
    let config_irq = msix.is_some() && transport.config_interrupt(1);
    if !config_irq {
        transport.no_config_interrupt();
    }
    // Interrupts are used once the handler can find the device (below).
    let queue = transport.setup_queue(0, 64, msix.map(|_| 0))?;
    let cursor_queue = transport.setup_queue(1, 16, None);
    transport.driver_ok();
    let n = (transport.config(|r| r(CFG_NUM_SCANOUTS)) as usize).clamp(1, MAX_SCANOUTS);
    let mut gpu = VirtioGpu {
        _transport: transport,
        queue,
        cursor_queue,
        edid: features & F_EDID != 0,
        minor: AtomicU32::new(0),
        scanouts: IrqSpinLock::new(alloc::vec![Scanout::default(); n]),
        next_id: AtomicU32::new(1),
        resources: IrqSpinLock::new(BTreeMap::new()),
        cursors: IrqSpinLock::new(BTreeMap::new()),
        console: None,
        console_shown: AtomicBool::new(false),
        damage: AtomicU64::new(0),
        damage_wake: WaitQueue::new(),
        config_changed: AtomicBool::new(false),
        config_wake: WaitQueue::new(),
    };
    let scanouts = gpu.read_scanouts();
    let (width, height) = match scanouts.first() {
        Some(s) if s.enabled => (s.width, s.height),
        _ => (1024, 768),
    };
    *gpu.scanouts.lock() = scanouts;
    // Carry the console when this is the machine's display. The firmware's
    // virtio-gpu driver offers no linear framebuffer (its GOP is blit-only),
    // so there is usually no console yet: give it one in RAM.
    if !other_display_adapter() && crate::drivers::fbcon::framebuffer().is_none() {
        console_in_ram(width, height);
    }
    if !other_display_adapter()
        && let Some(fb) = crate::drivers::fbcon::framebuffer()
        && fb.bpp == 32
    {
        // The backing: the framebuffer's pages, merged where contiguous.
        let bytes = (fb.pitch * fb.height) as u64;
        let mut pages: Vec<(u64, u32)> = Vec::new();
        let mut at = 0;
        while at < bytes {
            let Some(p) = crate::mm::virt_to_phys(fb.addr + at) else { break };
            match pages.last_mut() {
                Some((a, l)) if *a + u64::from(*l) == p.0 && *l < 1 << 20 => *l += PAGE_SIZE as u32,
                _ => pages.push((p.0, PAGE_SIZE as u32)),
            }
            at += PAGE_SIZE;
        }
        let (w, h, pitch) = ((fb.pitch / 4) as u32, fb.height as u32, fb.pitch as u32);
        match gpu.create(w, h, FORMAT_B8G8R8X8_UNORM, &pages) {
            Some(id) => gpu.console = Some(Console { id, width: fb.width as u32, height: h, pitch }),
            None => log_warn!("virtio-gpu: the console resource was refused"),
        }
    }
    let gpu = Arc::new(gpu);
    if gpu.console.is_some() {
        crate::drivers::drm::bootfb::claim();
        gpu.show_console();
        CONSOLE_GPU.call_once(|| gpu.clone());
        let g = gpu.clone();
        crate::sched::spawn("virtio-gpu-con", move || g.flush_console());
    }
    slot.call_once(|| gpu.clone());
    gpu.queue.set_interrupts(msix.is_some());
    log_info!(
        "virtio-gpu: {n} scanout{}, {width}x{height}{}{}{}, {}",
        if n == 1 { "" } else { "s" },
        if gpu.console.is_some() { ", console" } else { "" },
        if gpu.edid { ", EDID" } else { "" },
        if gpu.cursor_queue.is_some() { ", cursor" } else { "" },
        if msix.is_some() { "MSI-X" } else { "polled" }
    );
    let path = crate::drivers::pci_sys::path(gpu._transport.pci.address);
    let minor = drm::register(Box::new(gpu.clone()), &path, "pci");
    gpu.minor.store(minor, Ordering::Relaxed);
    if config_irq {
        let g = gpu.clone();
        crate::sched::spawn("virtio-gpu-events", move || g.display_events());
    }
    Some(())
}
