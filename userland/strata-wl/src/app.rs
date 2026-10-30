// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bridge: one Strata window for the compositor's one output.
//!
//! Start-up: open the window, connect to the compositor (the display
//! socket in `$XDG_RUNTIME_DIR`, watching the directory until it appears),
//! bind the globals, give the virtual keyboard its keymap, and size the
//! output to the window. Then, in turn: ask for a frame, have the
//! compositor copy it when it has damage (`copy_with_damage`), show it,
//! and ask again once Strata says the frame is on the screen (M31 phase
//! 2), or after [`FRAME_WAIT_MS`]. Keys,
//! pointer events and the wheel from Strata go to the virtual keyboard
//! and pointer; a new window size becomes a new output mode. Closing the
//! window, or the compositor going away, ends the program.
//!
//! Frames go straight into Strata's buffers where they can (M31 phase 2):
//! two files of shared memory are both wl_shm buffers for the compositor
//! and buffers given to Strata (opaque: XRGB8888's fourth byte means
//! nothing), so the compositor's copy is the only one, and Strata is told
//! the rectangles that changed. A frame of another size than the window
//! (while it resizes), in a format other than XRGB8888 or ARGB8888, or
//! upside down is copied into the window's canvas instead, as before.
//!
//! The clipboards go both ways (wlr-data-control): text the Linux side
//! selects is read through a pipe and copied to Strata's clipboard;
//! when the window gets the focus, Strata's clipboards are offered to the
//! Linux side. The title of the Linux side's active window
//! (wlr-foreign-toplevel-management) follows the program's name in the
//! window's title.
//!
//! The Linux side's idle inhibitors (a video playing in a browser) hold
//! off Strata's idle lock (ADR 0102's second addendum): with
//! ext-idle-notify-v1, the compositor says `idled` after [`IDLE_MS`]
//! without input unless something inhibits idling. No `idled` well after
//! the last input passed on means something does, and the window asks
//! Strata to hold off its lock until `idled` comes.
//!
//! Opcodes and argument orders are those of the protocol descriptions
//! named in the crate's documentation.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::mem::Mapping;
use slate_rt::{fs, io, lossy, process};
use slate_strata_client::{Connection, Event, MAX_TEXT, PointerKind, Window, clipboard};
use slate_ui::Canvas;

use crate::conn::{self, now_ms, shm_file, socket_path};
use crate::keymap;
use crate::pixels;
use crate::stats::FrameStats;
use crate::wire::{Args, Msg, Out};

/// What each object is (to read its events).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Display,
    Registry,
    Callback,
    Shm,
    Pool,
    Buffer,
    Seat,
    Output,
    Screencopy,
    Frame,
    KeyboardManager,
    Keyboard,
    PointerManager,
    Pointer,
    OutputManager,
    Head,
    Mode,
    Configuration,
    ConfigurationHead,
    DataManager,
    DataDevice,
    Offer,
    Source,
    ToplevelManager,
    Toplevel,
    IdleNotifier,
    IdleNotification,
}

/// How long without input before the compositor says `idled` (ms).
pub const IDLE_MS: u32 = 5000;

/// Whether the Linux side holds off idling: no `idled` although the last
/// input passed on was well over [`IDLE_MS`] ago.
pub fn held_off(idled: bool, now: i64, last_input: i64) -> bool {
    !idled && now - last_input > i64::from(IDLE_MS) + 2000
}

/// The text types offered and, in this order of preference, read.
const TEXT_TYPES: [&str; 5] = ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING", "TEXT", "STRING"];

fn board(which: u8) -> &'static str {
    if which == clipboard::SELECTION { "selection" } else { "clipboard" }
}

/// The text type to read from an offer of `types`.
fn text_type(types: &[String]) -> Option<&'static str> {
    TEXT_TYPES.into_iter().find(|t| types.iter().any(|o| o == t))
}

/// A Linux window's title and whether it is the active one
/// (zwlr_foreign_toplevel_handle_v1.state 2, activated).
#[derive(Debug, Default)]
struct Toplevel {
    title: String,
    pending: Option<String>,
    active: bool,
}

/// The title to show: the active window's, else the first with one.
fn shown_title(toplevels: &BTreeMap<u32, Toplevel>) -> Option<&str> {
    let titled = || toplevels.values().filter(|t| !t.title.is_empty());
    titled().find(|t| t.active).or_else(|| titled().next()).map(|t| t.title.as_str())
}

/// The Linux side's selection being read: the pipe, which clipboard, what
/// came so far.
struct Reading {
    fd: i32,
    which: u8,
    data: Vec<u8>,
}

type Wl = conn::Wl<Kind>;

/// The buffer frames are copied into: a shared-memory pool of one buffer.
struct ShmBuffer {
    pool: u32,
    buffer: u32,
    map: Mapping,
    fd: i32,
    size: (u32, u32, u32, u32),
}

/// One of the two buffers shared with both the compositor and Strata.
struct Direct {
    pool: u32,
    buffer: u32,
    map: Mapping,
    fd: i32,
    size: (u32, u32, u32, u32),
    /// Strata has it as this index of the window's buffers.
    given: bool,
}

/// A frame being captured.
#[derive(Debug, Default)]
struct Capture {
    id: u32,
    format: Option<(u32, u32, u32, u32)>,
    y_invert: bool,
    copying: bool,
    /// The rectangles the compositor said changed (x, y, w, h).
    damage: Vec<(u32, u32, u32, u32)>,
    /// When it was asked for (µs).
    asked: i64,
    /// The shared buffer it goes into, if it goes straight to Strata.
    direct: Option<u8>,
}

/// How long the bridge waits for Strata to say a frame is on the screen
/// before asking the compositor for the next anyway (a window not drawn,
/// minimised or on another workspace, still gets frames, more slowly).
pub const FRAME_WAIT_MS: i64 = 100;

/// The rows `damage` covers (top, bottom), within `height`; all of them if
/// it says nothing.
pub fn rows(damage: &[(u32, u32, u32, u32)], height: u32) -> (u32, u32) {
    let top = damage.iter().map(|d| d.1).min();
    let bottom = damage.iter().map(|d| d.1.saturating_add(d.3)).max();
    match (top, bottom) {
        (Some(t), Some(b)) => (t.min(height), b.min(height)),
        _ => (0, height),
    }
}

/// Whether a frame of `size` (wl_shm format, width, height, stride) can
/// go straight into Strata's buffers for a `window`-sized window: words
/// of 0xAARRGGBB rows with nothing between them, of the window's size.
pub fn direct_fits(size: (u32, u32, u32, u32), window: (u32, u32)) -> bool {
    let (format, w, h, stride) = size;
    matches!(format, pixels::XRGB8888 | pixels::ARGB8888) && stride == w * 4 && (w, h) == window && w > 0 && h > 0
}

struct Bridge {
    wl: Wl,
    conn: Connection,
    win: Window,
    canvas: Canvas,
    globals: Vec<(u32, String, u32)>,
    shm: u32,
    seat: u32,
    output: u32,
    screencopy: u32,
    screencopy_version: u32,
    keyboard: u32,
    pointer: u32,
    output_manager: u32,
    heads: Vec<u32>,
    serial: Option<u32>,
    /// An output configuration waiting for its answer.
    configuring: Option<u32>,
    /// The output size wanted and the size asked for last.
    want: (u32, u32),
    asked: (u32, u32),
    synced: Option<u32>,
    capture: Option<Capture>,
    shm_buffer: Option<ShmBuffer>,
    direct: [Option<Direct>; 2],
    /// Frames may go straight to Strata (none has come upside down).
    direct_ok: bool,
    /// A frame is wanted once Strata has shown the last: Strata's frame
    /// count when it was shown, and when (ms).
    want_frame: bool,
    shown_frames: u64,
    shown_at: i64,
    retry_at: Option<i64>,
    /// A whole frame must be shown (the window changed).
    full: bool,
    /// The program's name, the first part of the title.
    name: String,
    title: String,
    toplevels: BTreeMap<u32, Toplevel>,
    data_manager: u32,
    data_version: u32,
    data_device: u32,
    /// Offers and their types; the offer each clipboard holds.
    offers: BTreeMap<u32, Vec<String>>,
    current: [u32; 2],
    reading: Option<Reading>,
    /// Our sources: which clipboard and the text.
    sources: BTreeMap<u32, (u8, Vec<u8>)>,
    /// The text each clipboard last carried either way (so that it is not
    /// passed back where it came from).
    last: [Vec<u8>; 2],
    /// The idle notification (0: the compositor has none), whether it has
    /// said `idled`, when input was last passed on, and whether Strata
    /// was asked to hold off its lock.
    idle: u32,
    idled: bool,
    last_input: i64,
    holding: bool,
    /// Start-up's stages (M31 phase 1): the time the program was asked
    /// for (`SLATE_LINUX_T0`), the stages so far in ms since, and whether
    /// they have been told; frame timings with `strata.stats`.
    t0: u64,
    stages: Vec<(&'static str, u64)>,
    timed: bool,
    stats: Option<FrameStats>,
}

/// Linux's button codes (input-event-codes.h, ADR 0033).
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;

impl Bridge {
    /// Handle the compositor's events.
    fn handle(&mut self, msgs: Vec<Msg>) -> Result<(), String> {
        for m in msgs {
            let mut a = Args::new(&m.body);
            let kind = self.wl.kinds.get(&m.object).copied();
            match (kind, m.opcode) {
                (Some(Kind::Display), 0) => {
                    let (obj, code, msg) = (a.uint(), a.uint(), a.string());
                    return Err(format!("protocol error on object {obj:?} ({code:?}): {}", msg.unwrap_or_default()));
                }
                (Some(Kind::Display), 1) => {
                    if let Some(id) = a.uint() {
                        self.wl.kinds.remove(&id);
                    }
                }
                (Some(Kind::Registry), 0) => {
                    if let (Some(name), Some(iface), Some(version)) = (a.uint(), a.string(), a.uint()) {
                        self.globals.push((name, iface, version));
                    }
                }
                (Some(Kind::IdleNotification), 0) => self.idled = true,
                (Some(Kind::IdleNotification), 1) => self.idled = false,
                (Some(Kind::Callback), 0) => {
                    if self.synced == Some(m.object) {
                        self.synced = None;
                    }
                }
                (Some(Kind::OutputManager), 0) => {
                    if let Some(id) = a.uint() {
                        self.wl.kinds.insert(id, Kind::Head);
                        self.heads.push(id);
                    }
                }
                (Some(Kind::OutputManager), 1) => {
                    self.serial = a.uint();
                    self.resize_output()?;
                }
                (Some(Kind::Head), 3) => {
                    if let Some(id) = a.uint() {
                        self.wl.kinds.insert(id, Kind::Mode);
                    }
                }
                (Some(Kind::Head), 9) => self.heads.retain(|h| *h != m.object),
                (Some(Kind::Configuration), op @ 0..=2) => {
                    if op != 0 {
                        slate_rt::eprintln!("strata-wl: the compositor did not take the output size");
                    }
                    self.wl.send(Out::new(m.object, 4))?;
                    self.configuring = None;
                    if op == 2 {
                        // Cancelled (the outputs changed): ask again.
                        self.asked = (0, 0);
                    }
                    self.full = true;
                }
                (Some(Kind::Frame), 0) => {
                    if let (Some(format), Some(w), Some(h), Some(stride)) = (a.uint(), a.uint(), a.uint(), a.uint())
                        && pixels::supported(format)
                        && let Some(c) = self.capture.as_mut()
                    {
                        c.format = Some((format, w, h, stride));
                    }
                    // Before version 3 no buffer_done follows.
                    if self.screencopy_version < 3 {
                        self.copy()?;
                    }
                }
                (Some(Kind::Frame), 1) => {
                    if let (Some(flags), Some(c)) = (a.uint(), self.capture.as_mut()) {
                        c.y_invert = flags & 1 != 0;
                    }
                }
                (Some(Kind::Frame), 2) => self.ready(m.object)?,
                (Some(Kind::Frame), 3) => {
                    self.wl.send(Out::new(m.object, 1))?;
                    self.capture = None;
                    self.want_frame = true;
                    self.retry_at = Some(now_ms() + 100);
                }
                (Some(Kind::Frame), 4) => {
                    if let (Some(x), Some(y), Some(w), Some(h), Some(c)) =
                        (a.uint(), a.uint(), a.uint(), a.uint(), self.capture.as_mut())
                    {
                        c.damage.push((x, y, w, h));
                    }
                }
                (Some(Kind::Frame), 6) => self.copy()?,
                (Some(Kind::DataDevice), 0) => {
                    if let Some(id) = a.uint() {
                        self.wl.kinds.insert(id, Kind::Offer);
                        self.offers.insert(id, Vec::new());
                    }
                }
                (Some(Kind::Offer), 0) => {
                    if let (Some(t), Some(types)) = (a.string(), self.offers.get_mut(&m.object)) {
                        types.push(t);
                    }
                }
                (Some(Kind::DataDevice), op @ (1 | 3)) => {
                    let which = if op == 1 { clipboard::CLIPBOARD } else { clipboard::SELECTION };
                    self.selection(which, a.uint().unwrap_or(0))?;
                }
                (Some(Kind::DataDevice), 2) => self.data_device = 0,
                (Some(Kind::Source), 0) => {
                    let _mime = a.string();
                    if let Some(fd) = self.wl.fds.pop_front() {
                        if let Some((_, text)) = self.sources.get(&m.object) {
                            let _ = io::write_all(fd, text);
                        }
                        let _ = io::close(fd);
                    }
                }
                (Some(Kind::Source), 1) => {
                    self.sources.remove(&m.object);
                    self.wl.send(Out::new(m.object, 1))?;
                }
                (Some(Kind::ToplevelManager), 0) => {
                    if self.toplevels.is_empty() && !self.timed {
                        self.stage("app window");
                    }
                    if let Some(id) = a.uint() {
                        self.wl.kinds.insert(id, Kind::Toplevel);
                        self.toplevels.insert(id, Toplevel::default());
                    }
                }
                (Some(Kind::Toplevel), 0) => {
                    if let (Some(t), Some(top)) = (a.string(), self.toplevels.get_mut(&m.object)) {
                        top.pending = Some(t);
                    }
                }
                (Some(Kind::Toplevel), 4) => {
                    if let (Some(states), Some(top)) = (a.array(), self.toplevels.get_mut(&m.object)) {
                        top.active = states.as_chunks::<4>().0.iter().any(|c| u32::from_ne_bytes(*c) == 2);
                    }
                }
                (Some(Kind::Toplevel), 5) => {
                    if let Some(top) = self.toplevels.get_mut(&m.object)
                        && let Some(t) = top.pending.take()
                    {
                        top.title = t;
                    }
                    self.update_title()?;
                }
                (Some(Kind::Toplevel), 6) => {
                    self.toplevels.remove(&m.object);
                    self.wl.send(Out::new(m.object, 7))?;
                    self.update_title()?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The frames not yet summed up, as the bridge ends.
    fn flush_stats(&mut self) {
        if let Some(line) = self.stats.as_mut().and_then(|s| s.still(i64::MAX)) {
            slate_rt::eprintln!("{line}");
        }
    }

    /// Start-up reached `what` now.
    fn stage(&mut self, what: &'static str) {
        if !self.stages.iter().any(|s| s.0 == what) {
            self.stages.push((what, conn::since_ms(self.t0)));
        }
    }

    /// The window's title: the program's name and the active Linux
    /// window's title.
    fn update_title(&mut self) -> Result<(), String> {
        let t = String::from(shown_title(&self.toplevels).unwrap_or(""));
        if t != self.title {
            slate_rt::eprintln!("strata-wl: title \"{t}\"");
            self.conn.set_title(&self.win, &self.name, (!t.is_empty()).then_some(t.as_str()), 0)?;
            self.title = t;
        }
        Ok(())
    }

    /// A clipboard of the Linux side holds `offer` now (0: nothing): read
    /// its text, to copy it to Strata's.
    fn selection(&mut self, which: u8, offer: u32) -> Result<(), String> {
        let slot = usize::from(which);
        let old = core::mem::replace(&mut self.current[slot], offer);
        if old != 0 && old != offer && !self.current.contains(&old) {
            self.offers.remove(&old);
            self.wl.send(Out::new(old, 1))?;
        }
        let Some(mime) = self.offers.get(&offer).and_then(|t| text_type(t)) else { return Ok(()) };
        if let Some(r) = self.reading.take() {
            let _ = io::close(r.fd);
        }
        let (rd, wr) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("making a pipe: {e}"))?;
        let r = self.wl.send_fd(Out::new(offer, 0).string(mime), wr);
        let _ = io::close(wr);
        r?;
        self.reading = Some(Reading { fd: rd, which, data: Vec::new() });
        Ok(())
    }

    /// More of the Linux side's selection; at its end, copy it to Strata.
    fn read_selection(&mut self) -> Result<(), String> {
        let Some(r) = self.reading.as_mut() else { return Ok(()) };
        let mut buf = [0u8; 4096];
        let n = io::read(r.fd, &mut buf).unwrap_or(0);
        r.data.extend_from_slice(&buf[..n]);
        if n > 0 && r.data.len() <= MAX_TEXT {
            return Ok(());
        }
        let Some(r) = self.reading.take() else { return Ok(()) };
        let _ = io::close(r.fd);
        let slot = usize::from(r.which);
        if !r.data.is_empty() && r.data != self.last[slot] {
            slate_rt::eprintln!("strata-wl: {} bytes to Strata's {}", r.data.len(), board(r.which));
            self.conn.copy(r.which, &lossy(&r.data))?;
            self.last[slot] = r.data;
        }
        Ok(())
    }

    /// Strata's clipboard text: offer it to the Linux side.
    fn offer(&mut self, which: u8, text: String) -> Result<(), String> {
        let slot = usize::from(which);
        let primary = which == clipboard::SELECTION;
        if self.data_device == 0 || text.is_empty() || text.as_bytes() == self.last[slot] {
            return Ok(());
        }
        if primary && self.data_version < 2 {
            return Ok(());
        }
        let source = self.wl.id(Kind::Source);
        self.wl.send(Out::new(self.data_manager, 0).uint(source))?;
        for t in TEXT_TYPES {
            self.wl.send(Out::new(source, 0).string(t))?;
        }
        self.wl.send(Out::new(self.data_device, if primary { 2 } else { 0 }).uint(source))?;
        slate_rt::eprintln!("strata-wl: {} bytes from Strata's {}", text.len(), board(which));
        self.last[slot] = text.clone().into_bytes();
        self.sources.insert(source, (which, text.into_bytes()));
        Ok(())
    }

    /// Wait until the compositor has handled everything sent so far.
    fn roundtrip(&mut self) -> Result<(), String> {
        let cb = self.wl.id(Kind::Callback);
        self.wl.send(Out::new(1, 0).uint(cb))?;
        self.synced = Some(cb);
        while self.synced.is_some() {
            let msgs = self.wl.read()?;
            self.handle(msgs)?;
        }
        Ok(())
    }

    /// Bind the first global named `iface`, at most at `version`.
    fn bind(&mut self, registry: u32, iface: &str, version: u32, kind: Kind) -> Result<Option<(u32, u32)>, String> {
        let Some((name, _, v)) = self.globals.iter().find(|g| g.1 == iface).cloned() else { return Ok(None) };
        let v = v.min(version);
        let id = self.wl.id(kind);
        self.wl.send(Out::new(registry, 0).uint(name).string(iface).uint(v).uint(id))?;
        Ok(Some((id, v)))
    }

    /// Give the output the window's size, if it changed and nothing else
    /// is being configured.
    fn resize_output(&mut self) -> Result<(), String> {
        let (Some(serial), Some(&head)) = (self.serial, self.heads.first()) else { return Ok(()) };
        if self.configuring.is_some() || self.want == self.asked || self.output_manager == 0 {
            return Ok(());
        }
        let config = self.wl.id(Kind::Configuration);
        self.wl.send(Out::new(self.output_manager, 0).uint(config).uint(serial))?;
        let ch = self.wl.id(Kind::ConfigurationHead);
        self.wl.send(Out::new(config, 0).uint(ch).uint(head))?;
        self.wl.send(Out::new(ch, 1).int(self.want.0 as i32).int(self.want.1 as i32).int(0))?;
        self.wl.send(Out::new(config, 2))?;
        self.configuring = Some(config);
        self.asked = self.want;
        Ok(())
    }

    /// Ask for the next frame if one is wanted and Strata has shown the
    /// last (or hasn't said so for [`FRAME_WAIT_MS`]).
    fn maybe_capture(&mut self) -> Result<(), String> {
        if !self.want_frame || self.capture.is_some() || self.retry_at.is_some() {
            return Ok(());
        }
        // Somewhere to put it: a buffer Strata isn't reading (it lets the
        // last one go as soon as it has the next).
        if (0..2u8).all(|i| self.conn.held(&self.win, i)) {
            return Ok(());
        }
        if self.conn.frames(&self.win) > self.shown_frames || now_ms() - self.shown_at >= FRAME_WAIT_MS {
            self.want_frame = false;
            self.capture()?;
        }
        Ok(())
    }

    /// Ask for the next frame.
    fn capture(&mut self) -> Result<(), String> {
        let id = self.wl.id(Kind::Frame);
        self.wl.send(Out::new(self.screencopy, 0).uint(id).int(1).uint(self.output))?;
        self.capture = Some(Capture { id, asked: conn::now_us(), ..Capture::default() });
        Ok(())
    }

    /// The frame's buffer is described: copy into ours.
    fn copy(&mut self) -> Result<(), String> {
        let Some(c) = self.capture.as_mut() else { return Ok(()) };
        if c.copying {
            return Ok(());
        }
        let Some(size) = c.format else {
            return Err("the compositor offers frames in no format this program reads".into());
        };
        c.copying = true;
        let frame = c.id;
        let op = if self.screencopy_version >= 2 { 2 } else { 0 };
        // Straight into the buffer Strata isn't reading, where it fits.
        let window = (self.win.width, self.win.height);
        let free = (0..2u8).find(|&i| !self.conn.held(&self.win, i));
        if let Some(i) = free.filter(|_| self.direct_ok && direct_fits(size, window)) {
            let buffer = self.direct_buffer(i, size)?;
            if let Some(c) = self.capture.as_mut() {
                c.direct = Some(i);
            }
            return self.wl.send(Out::new(frame, op).uint(buffer));
        }
        if self.shm_buffer.as_ref().is_none_or(|b| b.size != size) {
            if let Some(old) = self.shm_buffer.take() {
                self.wl.send(Out::new(old.buffer, 0))?;
                self.wl.send(Out::new(old.pool, 1))?;
                let _ = io::close(old.fd);
            }
            let (format, w, h, stride) = size;
            let len = (stride * h) as usize;
            let fd = shm_file(len)?;
            let map = Mapping::shared(fd, len, 0).map_err(|e| format!("mapping a frame buffer: {e}"))?;
            let pool = self.wl.id(Kind::Pool);
            self.wl.send_fd(Out::new(self.shm, 0).uint(pool).int(len as i32), fd)?;
            let buffer = self.wl.id(Kind::Buffer);
            self.wl.send(
                Out::new(pool, 0).uint(buffer).int(0).int(w as i32).int(h as i32).int(stride as i32).uint(format),
            )?;
            self.shm_buffer = Some(ShmBuffer { pool, buffer, map, fd, size });
            self.full = true;
        }
        let buffer = self.shm_buffer.as_ref().map_or(0, |b| b.buffer);
        self.wl.send(Out::new(frame, op).uint(buffer))
    }

    /// Shared buffer `i`, of `size`, made (and given to Strata) if need be:
    /// its wl_buffer.
    fn direct_buffer(&mut self, i: u8, size: (u32, u32, u32, u32)) -> Result<u32, String> {
        let slot = usize::from(i);
        if self.direct[slot].as_ref().is_none_or(|d| d.size != size) {
            if let Some(old) = self.direct[slot].take() {
                self.wl.send(Out::new(old.buffer, 0))?;
                self.wl.send(Out::new(old.pool, 1))?;
                let _ = io::close(old.fd);
            }
            let (format, w, h, stride) = size;
            let len = (stride * h) as usize;
            let fd = shm_file(len)?;
            let map = Mapping::shared(fd, len, 0).map_err(|e| format!("mapping a frame buffer: {e}"))?;
            let pool = self.wl.id(Kind::Pool);
            self.wl.send_fd(Out::new(self.shm, 0).uint(pool).int(len as i32), fd)?;
            let buffer = self.wl.id(Kind::Buffer);
            self.wl.send(
                Out::new(pool, 0).uint(buffer).int(0).int(w as i32).int(h as i32).int(stride as i32).uint(format),
            )?;
            self.direct[slot] = Some(Direct { pool, buffer, map, fd, size, given: false });
            self.full = true;
        }
        let Some(d) = self.direct[slot].as_mut() else { return Err("no shared buffer".into()) };
        if !d.given {
            let (_, w, h, _) = d.size;
            self.conn.give(&self.win, i, d.fd, w, h, true)?;
            d.given = true;
        }
        Ok(d.buffer)
    }

    /// A frame is in our buffer: show it, and want the next.
    fn ready(&mut self, frame: u32) -> Result<(), String> {
        let Some(c) = self.capture.take() else { return Ok(()) };
        self.wl.send(Out::new(frame, 1))?;
        self.want_frame = true;
        let Some((format, w, h, stride)) = c.format else { return Ok(()) };
        // Upside down: never straight to Strata again.
        if c.direct.is_some() && c.y_invert {
            self.direct_ok = false;
        }
        if let Some(i) = c.direct.filter(|_| !c.y_invert) {
            // In Strata's buffer already: say where it changed.
            let t = conn::now_us();
            let rects = if self.full || c.damage.is_empty() { alloc::vec![(0, 0, w, h)] } else { c.damage };
            self.full = false;
            self.conn.show(&self.win, i, &rects)?;
            let shown = conn::now_us();
            if let Some(s) = self.stats.as_mut() {
                // The compositor's copy into the shared buffer, only.
                s.frame(shown, t - c.asked, 0, shown - t, u64::from(stride * h));
            }
        } else {
            let data = match c.direct {
                Some(i) => self.direct[usize::from(i)].as_mut().map(|d| d.map.as_mut_slice()),
                None => self.shm_buffer.as_mut().map(|b| b.map.as_mut_slice()),
            };
            let Some(data) = data else { return Ok(()) };
            let f = pixels::Frame { data, width: w, height: h, stride, format, y_invert: c.y_invert };
            let (cw, ch) = (self.canvas.width as u32, self.canvas.height as u32);
            let (top, bottom) = if self.full || c.y_invert { (0, ch) } else { rows(&c.damage, ch) };
            let t = conn::now_us();
            pixels::copy(&f, &mut self.canvas.pixels, cw, ch, top, bottom);
            let copied = conn::now_us();
            self.full = false;
            self.conn.present(&mut self.win, &self.canvas)?;
            // present() put buffers of its own where the shared ones were.
            for d in self.direct.iter_mut().flatten() {
                d.given = false;
            }
            let shown = conn::now_us();
            if let Some(s) = self.stats.as_mut() {
                // Sway's whole frame into ours, the damaged rows into the
                // canvas, then the canvas compared with Strata's buffer
                // (at most all of it) and what changed copied.
                let rows = u64::from(bottom.min(ch).saturating_sub(top));
                let bytes = u64::from(stride * h) + rows * u64::from(cw) * 4 * 2 + u64::from(cw * ch) * 4;
                s.frame(shown, t - c.asked, copied - t, shown - copied, bytes);
            }
        }
        self.shown_frames = self.conn.frames(&self.win);
        self.shown_at = now_ms();
        // The first frame with the program's window in it ends start-up.
        if !self.timed && !self.toplevels.is_empty() {
            self.stage("first frame");
            self.timed = true;
            let parts: Vec<String> = self.stages.iter().map(|(w, ms)| format!("{w} {ms} ms")).collect();
            slate_rt::eprintln!("strata-wl: timing: {}", parts.join(", "));
        }
        Ok(())
    }

    /// A Strata event; false when the window was closed.
    fn strata(&mut self, e: Event) -> Result<bool, String> {
        let t = now_ms() as u32;
        if matches!(e, Event::Key { .. } | Event::Pointer { .. } | Event::Scroll { .. }) {
            self.last_input = now_ms();
        }
        match e {
            Event::Configure { .. } => {
                let was = self.win.focused;
                let resized = self.win.configure(&e);
                // Focused: what Strata's clipboards hold goes to the Linux side.
                if self.win.focused && !was && self.data_device != 0 {
                    self.conn.paste(&self.win, clipboard::CLIPBOARD)?;
                    self.conn.paste(&self.win, clipboard::SELECTION)?;
                }
                if resized {
                    self.canvas = self.win.canvas(slate_ui::Color::rgb(0));
                    self.want = (self.win.width, self.win.height);
                    self.full = true;
                    self.resize_output()?;
                }
            }
            // A dead key's accent typed by itself (ADR 0117): no key of its
            // own; the Linux program composes from the keys for itself.
            Event::Key { code: 0, .. } => {}
            Event::Key { code, ch, mods, .. } => {
                let (depressed, locked) = keymap::masks(mods, char::from_u32(ch).filter(|_| ch != 0));
                let k = self.keyboard;
                self.wl.send(Out::new(k, 2).uint(depressed).uint(0).uint(locked).uint(0))?;
                self.wl.send(Out::new(k, 1).uint(t).uint(u32::from(code)).uint(1))?;
                self.wl.send(Out::new(k, 1).uint(t).uint(u32::from(code)).uint(0))?;
                self.wl.send(Out::new(k, 2).uint(0).uint(0).uint(locked).uint(0))?;
            }
            Event::Pointer { kind, button, x, y, .. } => {
                let (w, h) = (self.win.width.max(1), self.win.height.max(1));
                let (x, y) = (x.clamp(0, w as i32 - 1) as u32, y.clamp(0, h as i32 - 1) as u32);
                let p = self.pointer;
                self.wl.send(Out::new(p, 1).uint(t).uint(x).uint(y).uint(w).uint(h))?;
                if kind != PointerKind::Move {
                    let code = match button {
                        2 => BTN_MIDDLE,
                        3 => BTN_RIGHT,
                        _ => BTN_LEFT,
                    };
                    self.wl.send(Out::new(p, 2).uint(t).uint(code).uint(u32::from(kind == PointerKind::Down)))?;
                }
                self.wl.send(Out::new(p, 4))?;
            }
            Event::Scroll { lines, .. } => {
                let p = self.pointer;
                // A wheel (axis source 0), vertical (axis 0), 15 units a notch.
                self.wl.send(Out::new(p, 5).uint(0))?;
                self.wl.send(Out::new(p, 7).uint(t).uint(0).fixed(15.0 * lines as f32).int(lines))?;
                self.wl.send(Out::new(p, 4))?;
            }
            Event::Close { .. } => return Ok(false),
            Event::Paste { which, text, .. } => self.offer(which, text)?,
            // Taken by the client library itself.
            Event::Release { .. } | Event::Frame { .. } => {}
            // Linux programs aren't sent drops (ADR 0156).
            Event::Drop { .. } => {}
        }
        Ok(true)
    }
}

/// Connect to the compositor's socket in `dir`, waiting up to 30 s for it
/// to appear: the directory is watched (inotify(7)), so the bridge
/// connects as soon as the compositor has made it, not at its next look
/// (M31 phase 2: it looked every 100 ms). Without a watch it looks every
/// 5 ms.
fn wait_compositor(dir: &[u8]) -> Result<Wl, String> {
    use slate_abi::watch as w;
    let watch = fs::watch_open(true).ok().filter(|&fd| {
        let ok = fs::watch_add(fd, dir, w::CREATE | w::MOVED_TO).is_ok();
        if !ok {
            let _ = io::close(fd);
        }
        ok
    });
    let deadline = now_ms() + 30_000;
    let mut last = String::from("no compositor's socket appeared");
    let r = loop {
        if let Some(path) = socket_path(dir) {
            match Wl::connect(&path, Kind::Display) {
                Ok(wl) => break Ok(wl),
                // Made, not yet listening.
                Err(e) => last = e,
            }
        }
        let left = deadline - now_ms();
        if left <= 0 {
            break Err(last);
        }
        match watch {
            Some(fd) => {
                let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
                // (Short, for a socket made but not yet listening.)
                let _ = io::poll(&mut p, left.min(if last.contains("appeared") { 1000 } else { 5 }) as i32);
                let mut buf = [0u8; 1024];
                while io::read(fd, &mut buf).is_ok_and(|n| n > 0) {}
            }
            None => {
                slate_rt::time::sleep_ns(5_000_000);
            }
        }
    };
    if let Some(fd) = watch {
        let _ = io::close(fd);
    }
    r
}

pub fn main() -> i32 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("strata-wl: {e}");
            1
        }
    }
}

fn run() -> Result<(), String> {
    // A clipboard's reader may close its pipe before the text is written
    // (strata-wl reading back its own offer, replaced by the next one):
    // that write fails with EPIPE rather than ending the bridge.
    let _ = slate_rt::signal::set(slate_rt::signal::SIGPIPE, slate_rt::signal::Disposition::Ignore);
    let args = slate_rt::env::args();
    let title = args.get(1).map(|a| String::from(lossy(a))).unwrap_or_else(|| String::from("linux app"));
    let t0 = conn::t0_ns();
    let mut conn = Connection::connect()?;
    let win = conn.create(&title, None)?;
    let window_ms = conn::since_ms(t0);
    let dir = slate_rt::env::var(b"XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
    let wl = wait_compositor(&dir)?;
    let connected_ms = conn::since_ms(t0);
    let canvas = win.canvas(slate_ui::Color::rgb(0));
    let want = (win.width, win.height);
    let mut b = Bridge {
        wl,
        conn,
        win,
        canvas,
        globals: Vec::new(),
        shm: 0,
        seat: 0,
        output: 0,
        screencopy: 0,
        screencopy_version: 0,
        keyboard: 0,
        pointer: 0,
        output_manager: 0,
        heads: Vec::new(),
        serial: None,
        configuring: None,
        want,
        asked: (0, 0),
        synced: None,
        capture: None,
        shm_buffer: None,
        direct: [None, None],
        direct_ok: true,
        want_frame: false,
        shown_frames: 0,
        shown_at: 0,
        retry_at: None,
        full: true,
        name: title.clone(),
        title: String::new(),
        toplevels: BTreeMap::new(),
        data_manager: 0,
        data_version: 0,
        data_device: 0,
        offers: BTreeMap::new(),
        current: [0; 2],
        reading: None,
        sources: BTreeMap::new(),
        last: [Vec::new(), Vec::new()],
        idle: 0,
        idled: false,
        last_input: now_ms(),
        holding: false,
        t0,
        stages: alloc::vec![("window", window_ms), ("compositor", connected_ms)],
        timed: false,
        stats: None,
    };
    let registry = b.wl.id(Kind::Registry);
    b.wl.send(Out::new(1, 1).uint(registry))?;
    b.roundtrip()?;
    let need = |r: Option<(u32, u32)>, what: &str| r.ok_or_else(|| format!("the compositor has no {what}"));
    b.shm = need(b.bind(registry, "wl_shm", 1, Kind::Shm)?, "wl_shm")?.0;
    b.seat = need(b.bind(registry, "wl_seat", 1, Kind::Seat)?, "wl_seat")?.0;
    b.output = need(b.bind(registry, "wl_output", 1, Kind::Output)?, "wl_output")?.0;
    let sc = need(b.bind(registry, "zwlr_screencopy_manager_v1", 3, Kind::Screencopy)?, "screencopy")?;
    (b.screencopy, b.screencopy_version) = sc;
    let km = need(b.bind(registry, "zwp_virtual_keyboard_manager_v1", 1, Kind::KeyboardManager)?, "virtual keyboard")?;
    let pm = need(b.bind(registry, "zwlr_virtual_pointer_manager_v1", 1, Kind::PointerManager)?, "virtual pointer")?;
    b.output_manager = b.bind(registry, "zwlr_output_manager_v1", 1, Kind::OutputManager)?.map_or(0, |o| o.0);
    // The clipboards and window titles, when the compositor has them.
    if let Some((dm, v)) = b.bind(registry, "zwlr_data_control_manager_v1", 2, Kind::DataManager)? {
        (b.data_manager, b.data_version) = (dm, v);
        b.data_device = b.wl.id(Kind::DataDevice);
        b.wl.send(Out::new(dm, 1).uint(b.data_device).uint(b.seat))?;
    }
    let toplevels = b.bind(registry, "zwlr_foreign_toplevel_manager_v1", 3, Kind::ToplevelManager)?.is_some();
    // Idling, as the compositor sees it with its inhibitors
    // (ext_idle_notifier_v1.get_idle_notification: id, timeout, seat).
    if let Some((notifier, _)) = b.bind(registry, "ext_idle_notifier_v1", 1, Kind::IdleNotifier)? {
        b.idle = b.wl.id(Kind::IdleNotification);
        b.wl.send(Out::new(notifier, 1).uint(b.idle).uint(IDLE_MS).uint(b.seat))?;
    }
    // The virtual keyboard, with its keymap (NUL-terminated, as
    // wl_keyboard.keymap's are).
    b.keyboard = b.wl.id(Kind::Keyboard);
    b.wl.send(Out::new(km.0, 0).uint(b.seat).uint(b.keyboard))?;
    let cmdline = fs::read_file(b"/proc/cmdline").map(|c| String::from(lossy(&c))).unwrap_or_default();
    if cmdline.split_whitespace().any(|w| w == "strata.stats") {
        b.stats = Some(FrameStats::default());
    }
    let layout = cmdline
        .split_whitespace()
        .find_map(|w| w.strip_prefix("slate.keyboard="))
        .map(String::from)
        .or_else(|| slate_rt::env::var(b"SLATE_KEYBOARD").map(|k| String::from(lossy(&k))))
        .unwrap_or_default();
    let mut text = keymap::keymap(slate_display::input::Layout::named(&layout)).into_bytes();
    text.push(0);
    let fd = shm_file(text.len())?;
    io::write_all(fd, &text).map_err(|e| format!("writing the keymap: {e}"))?;
    // Format 1: XKB keymap text (wl_keyboard.keymap_format.xkb_v1).
    b.wl.send_fd(Out::new(b.keyboard, 0).uint(1).uint(text.len() as u32), fd)?;
    let _ = io::close(fd);
    b.pointer = b.wl.id(Kind::Pointer);
    b.wl.send(Out::new(pm.0, 0).uint(b.seat).uint(b.pointer))?;
    b.roundtrip()?;
    b.stage("bound");
    b.resize_output()?;
    b.want_frame = true;
    b.maybe_capture()?;
    slate_rt::eprintln!(
        "strata-wl: showing {title} ({}x{}; screencopy v{}{}{}{}{})",
        b.win.width,
        b.win.height,
        b.screencopy_version,
        if b.output_manager != 0 { ", output management" } else { "" },
        if b.data_device != 0 { ", clipboard" } else { "" },
        if toplevels { ", titles" } else { "" },
        if b.idle != 0 { ", idle inhibitors" } else { "" }
    );
    loop {
        let mut timeout = b.retry_at.map_or(-1, |at| (at - now_ms()).max(0) as i32);
        // Idling is looked at each second.
        if b.idle != 0 {
            timeout = if timeout < 0 { 1000 } else { timeout.min(1000) };
        }
        // A frame wanted waits for Strata's word, or not long.
        if b.want_frame && b.capture.is_none() {
            let t = (b.shown_at + FRAME_WAIT_MS - now_ms()).clamp(0, FRAME_WAIT_MS) as i32;
            timeout = if timeout < 0 { t } else { timeout.min(t) };
        }
        // A summary is looked for once frames stop.
        if b.stats.as_ref().is_some_and(FrameStats::pending) {
            let t = (crate::stats::STILL_US / 1000) as i32;
            timeout = if timeout < 0 { t } else { timeout.min(t) };
        }
        if let Some(line) = b.stats.as_mut().and_then(|s| s.still(conn::now_us())) {
            slate_rt::eprintln!("{line}");
        }
        if b.idle != 0 {
            let hold = held_off(b.idled, now_ms(), b.last_input);
            if hold != b.holding {
                b.holding = hold;
                slate_rt::eprintln!("strata-wl: the Linux side {} idling", if hold { "holds off" } else { "allows" });
                b.conn.inhibit(&b.win, hold)?;
            }
        }
        let mut fds = [
            io::PollFd { fd: b.wl.fd, events: io::POLLIN, revents: 0 },
            io::PollFd { fd: b.conn.fd(), events: io::POLLIN, revents: 0 },
            io::PollFd { fd: b.reading.as_ref().map_or(-1, |r| r.fd), events: io::POLLIN, revents: 0 },
        ];
        let _ = io::poll(&mut fds, timeout);
        if fds[2].revents != 0 {
            b.read_selection()?;
        }
        if b.retry_at.is_some_and(|at| now_ms() >= at) {
            b.retry_at = None;
        }
        if fds[0].revents != 0 {
            match b.wl.read() {
                Ok(msgs) => b.handle(msgs)?,
                Err(_) => {
                    b.flush_stats();
                    return Ok(());
                }
            }
        }
        if fds[1].revents != 0 {
            b.conn.read()?;
            for e in b.conn.take_events() {
                if !b.strata(e)? {
                    b.flush_stats();
                    return Ok(());
                }
            }
        }
        b.maybe_capture()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_types() {
        let offer = |t: &[&str]| t.iter().map(|s| String::from(*s)).collect::<Vec<_>>();
        assert_eq!(text_type(&offer(&["image/png", "UTF8_STRING", "text/plain"])), Some("text/plain"));
        assert_eq!(text_type(&offer(&["text/plain;charset=utf-8", "STRING"])), Some("text/plain;charset=utf-8"));
        assert_eq!(text_type(&offer(&["image/png"])), None);
    }

    #[test]
    fn damage_and_direct_frames() {
        assert_eq!(rows(&[], 600), (0, 600));
        assert_eq!(rows(&[(0, 10, 5, 5), (3, 40, 9, 2)], 600), (10, 42));
        assert_eq!(rows(&[(0, 590, 5, 50)], 600), (590, 600));
        let (x, a, b) = (pixels::XRGB8888, pixels::ARGB8888, pixels::XBGR8888);
        assert!(direct_fits((x, 800, 600, 3200), (800, 600)));
        assert!(direct_fits((a, 800, 600, 3200), (800, 600)));
        // Red and blue the other way, padded rows, another size.
        assert!(!direct_fits((b, 800, 600, 3200), (800, 600)));
        assert!(!direct_fits((x, 800, 600, 3328), (800, 600)));
        assert!(!direct_fits((x, 800, 600, 3200), (801, 600)));
        assert!(!direct_fits((x, 0, 0, 0), (0, 0)));
    }

    #[test]
    fn idle_inhibitors() {
        // Input 1 s ago: not yet; 8 s ago and never idled: held off;
        // idled: not.
        assert!(!held_off(false, 10_000, 9_000));
        assert!(held_off(false, 10_000, 2_000));
        assert!(!held_off(true, 10_000, 2_000));
    }

    #[test]
    fn titles() {
        let mut t = BTreeMap::new();
        assert_eq!(shown_title(&t), None);
        t.insert(3, Toplevel { title: "Downloads".into(), pending: None, active: false });
        assert_eq!(shown_title(&t), Some("Downloads"));
        t.insert(4, Toplevel { title: "Slate — Mozilla Firefox".into(), pending: None, active: true });
        assert_eq!(shown_title(&t), Some("Slate — Mozilla Firefox"));
        t.insert(5, Toplevel { title: String::new(), pending: None, active: true });
        assert_eq!(shown_title(&t), Some("Slate — Mozilla Firefox"));
    }
}
