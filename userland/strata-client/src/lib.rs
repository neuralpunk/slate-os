// SPDX-License-Identifier: MIT OR Apache-2.0

//! The library Strata's apps use (ADR 0037): connect to the session's
//! Strata, open windows, draw each into a slate-ui canvas and present it
//! through shared memory, and read the events Strata sends. Each window
//! has two buffers: a frame is copied into the one Strata isn't showing,
//! which then is shown, so Strata never reads a half-copied frame
//! (ADR 0039). Only what changed is copied and sent as damage (ADR
//! 0065): the frame is compared with the buffer shown last, and the
//! other buffer is brought up to date with what it missed meanwhile.
//!
//! An app whose pixels another program writes (strata-wl, whose
//! compositor copies its frames straight into them; M31) gives Strata its
//! own buffers instead (`give`) and says which to show (`show`); Strata's
//! `Frame` events say when what was shown is on the screen (`frames`).
//!
//! The socket is the abstract name in `STRATA_SOCKET` (Strata sets it for
//! the programs it starts), or `strata-<uid>`.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::mem::Mapping;
use slate_rt::{fs, io, lossy, net, process};
use slate_ui::{Canvas, Rect};
pub use strata_proto::{Event, MAX_TEXT, PointerKind, clipboard, cursor, mods, urgency};
use strata_proto::{Next, Request};

/// The socket's name for this user.
pub fn socket_name() -> Vec<u8> {
    slate_rt::env::var(b"STRATA_SOCKET").unwrap_or_else(|| format!("strata-{}", process::getuid()).into_bytes())
}

/// A connection to Strata.
#[derive(Debug)]
pub struct Connection {
    fd: i32,
    inbuf: Vec<u8>,
    pending: VecDeque<Event>,
    next_win: u32,
    /// Each window's two buffers, and which Strata still holds.
    buffers: BTreeMap<u32, Buffers>,
    /// Buffers made so far (their files' names).
    files: u32,
}

/// A window's two buffers.
#[derive(Debug, Default)]
struct Buffers {
    shm: [Option<Shm>; 2],
    /// Strata may be reading it (shown, not yet released).
    held: [bool; 2],
    /// The buffer shown last.
    shown: Option<usize>,
    /// Where each buffer differs from the frame shown last.
    stale: [Rect; 2],
    /// The app gave this buffer itself ([`Connection::give`]).
    given: [bool; 2],
    /// The frames Strata has said were shown.
    frames: u64,
}

/// The smallest rectangle where the `w`-pixel-wide images `a` and `b`
/// differ; `None` if they are the same.
fn changed(a: &[u32], b: &[u32], w: usize) -> Option<Rect> {
    if w == 0 {
        return None;
    }
    let rows = a.len().min(b.len()) / w;
    let differs = |y: usize| a[y * w..(y + 1) * w] != b[y * w..(y + 1) * w];
    let top = (0..rows).find(|&y| differs(y))?;
    let bottom = (top..rows).rev().find(|&y| differs(y)).unwrap_or(top);
    let (mut left, mut right) = (w, 0);
    for y in top..=bottom {
        let (ra, rb) = (&a[y * w..(y + 1) * w], &b[y * w..(y + 1) * w]);
        if let Some(l) = ra.iter().zip(rb).position(|(p, q)| p != q) {
            left = left.min(l);
            let r = ra.iter().zip(rb).rposition(|(p, q)| p != q).unwrap_or(l);
            right = right.max(r + 1);
        }
    }
    Some(Rect::new(left as i32, top as i32, (right - left) as i32, (bottom - top + 1) as i32))
}

/// Copy `r` of the `w`-pixel-wide image `src` into `dst`.
fn copy_rect(dst: &mut [u32], src: &[u32], w: usize, r: Rect) {
    for y in r.y as usize..r.bottom() as usize {
        let (a, b) = (y * w + r.x as usize, y * w + r.right() as usize);
        if b <= src.len() && b <= dst.len() {
            dst[a..b].copy_from_slice(&src[a..b]);
        }
    }
}

impl Connection {
    pub fn connect() -> Result<Connection, String> {
        Connection::connect_to(&socket_name())
    }

    /// Connect to the Strata listening on the abstract socket `name`.
    pub fn connect_to(name: &[u8]) -> Result<Connection, String> {
        let fd = net::connect(name).map_err(|e| format!("cannot reach Strata (@{}): {e}", lossy(name)))?;
        let mut c = Connection {
            fd,
            inbuf: Vec::new(),
            pending: VecDeque::new(),
            next_win: 1,
            buffers: BTreeMap::new(),
            files: 0,
        };
        c.send(&Request::Hello { version: strata_proto::VERSION })?;
        Ok(c)
    }

    /// The socket, to poll alongside other descriptors.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    fn send(&mut self, r: &Request) -> Result<(), String> {
        io::write_all(self.fd, &r.encode()).map_err(|e| format!("talking to Strata: {e}"))
    }

    /// Read what has arrived (the socket must be readable, or this blocks).
    /// Err when Strata has gone.
    pub fn read(&mut self) -> Result<(), String> {
        let mut buf = [0u8; 4096];
        let n = io::read(self.fd, &mut buf).map_err(|e| format!("reading from Strata: {e}"))?;
        if n == 0 {
            return Err("Strata has gone".into());
        }
        self.inbuf.extend_from_slice(&buf[..n]);
        loop {
            match strata_proto::next_event(&mut self.inbuf) {
                // A buffer Strata no longer reads: ours to draw into.
                Next::Message(Event::Release { win, index }) => {
                    if let Some(h) = self.buffers.get_mut(&win).and_then(|b| b.held.get_mut(usize::from(index))) {
                        *h = false;
                    }
                }
                // What was shown is on the screen.
                Next::Message(Event::Frame { win }) => self.buffers.entry(win).or_default().frames += 1,
                Next::Message(e) => self.pending.push_back(e),
                Next::Incomplete => return Ok(()),
                Next::Broken => return Err("Strata sent something unreadable".into()),
            }
        }
    }

    /// Wait up to `timeout_ms` for events (-1: for ever).
    pub fn poll(&mut self, timeout_ms: i32) -> Result<Vec<Event>, String> {
        if self.pending.is_empty() {
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, timeout_ms).unwrap_or(0) > 0 {
                self.read()?;
            }
        }
        Ok(self.pending.drain(..).collect())
    }

    /// The events read so far.
    pub fn take_events(&mut self) -> Vec<Event> {
        self.pending.drain(..).collect()
    }

    /// Open a window titled `app` (and `path`), and wait for its size.
    pub fn create(&mut self, app: &str, path: Option<&str>) -> Result<Window, String> {
        let id = self.next_win;
        self.next_win += 1;
        self.send(&Request::Create { win: id, app: String::from(app), path: String::from(path.unwrap_or("")) })?;
        let mut w = Window { id, width: 0, height: 0, scale: 1.0, focused: false };
        // Strata answers with the window's size; other events wait.
        for _ in 0..500 {
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, 10).unwrap_or(0) > 0 {
                self.read()?;
            }
            if let Some(i) = self.pending.iter().position(|e| matches!(e, Event::Configure { win, .. } if *win == id)) {
                let e = self.pending.remove(i).unwrap_or(Event::Close { win: id });
                w.configure(&e);
                return Ok(w);
            }
        }
        Err("Strata did not answer".into())
    }

    /// Ask for sizes (logical pixels; 0: none): the smallest the window
    /// takes, and the size it would like (ADR 0102). Strata keeps the
    /// window at least that large when the person resizes it.
    pub fn set_hints(&mut self, w: &Window, min: (u32, u32), size: (u32, u32)) -> Result<(), String> {
        self.send(&Request::Hints { win: w.id, min_width: min.0, min_height: min.1, width: size.0, height: size.1 })
    }

    /// Resize in steps (logical pixels): the content is `base` and a
    /// whole number of `step`s when the person resizes the window (a
    /// terminal's cells; ADR 0102's third addendum).
    pub fn set_steps(&mut self, w: &Window, base: (f32, f32), step: (f32, f32)) -> Result<(), String> {
        let c = |v: f32| (v.max(0.0) * 100.0 + 0.5) as u32;
        self.send(&Request::Steps {
            win: w.id,
            base_width: c(base.0),
            base_height: c(base.1),
            width: c(step.0),
            height: c(step.1),
        })
    }

    /// Keep the screen from locking by itself while `on` (a video
    /// playing), or let it again.
    pub fn inhibit(&mut self, w: &Window, on: bool) -> Result<(), String> {
        self.send(&Request::Inhibit { win: w.id, on })
    }

    /// A notification (ADR 0186): `key` (not 0) replaces this app's
    /// earlier one with the same key; `urgency` is `strata_proto::urgency`.
    pub fn notify(&mut self, key: u32, app: &str, summary: &str, body: &str, urgency: u8) -> Result<(), String> {
        self.send(&Request::Notify {
            key,
            app: String::from(app),
            summary: String::from(summary),
            body: String::from(body),
            urgency,
        })
    }

    /// This app's notification `key` is no longer wanted.
    pub fn unnotify(&mut self, key: u32) -> Result<(), String> {
        self.send(&Request::Unnotify { key })
    }

    /// The pointer's shape over `w`'s content (`strata_proto::cursor::*`;
    /// ADR 0186).
    pub fn set_cursor(&mut self, w: &Window, shape: u8) -> Result<(), String> {
        self.send(&Request::Cursor { win: w.id, shape })
    }

    /// A new title for `w`, naming the process it shows (`pid`, a child of
    /// this app; 0 for the app itself), whose domain Strata shows.
    pub fn set_title(&mut self, w: &Window, app: &str, path: Option<&str>, pid: i32) -> Result<(), String> {
        let r = Request::Title {
            win: w.id,
            app: String::from(app),
            path: String::from(path.unwrap_or("")),
            pid: pid.max(0) as u32,
        };
        self.send(&r)
    }

    /// Offer `text` as a clipboard's (`clipboard::*`); Strata takes it
    /// while this app has the focused window.
    pub fn copy(&mut self, which: u8, text: &str) -> Result<(), String> {
        self.send(&Request::Copy { which, text: String::from(strata_proto::cut(text, MAX_TEXT)) })
    }

    /// Ask for a clipboard's text: it comes as `Event::Paste` if `w` has
    /// the focus.
    pub fn paste(&mut self, w: &Window, which: u8) -> Result<(), String> {
        self.send(&Request::Paste { win: w.id, which })
    }

    /// Say that `paths` are being dragged out of `w` with the left button
    /// held (ADR 0156): dropped outside it, they go onto the desktop or to
    /// the window there (`Event::Drop`).
    pub fn drag(&mut self, w: &Window, paths: &[String]) -> Result<(), String> {
        self.send(&Request::Drag { win: w.id, paths: paths.join("\n") })
    }

    pub fn destroy(&mut self, w: Window) -> Result<(), String> {
        self.buffers.remove(&w.id);
        self.send(&Request::Destroy { win: w.id })
    }

    /// Show `canvas` (the window's size) in `w`: copied into the buffer
    /// Strata isn't reading (waiting up to a second for it to let one go),
    /// then shown.
    pub fn present(&mut self, w: &mut Window, canvas: &Canvas) -> Result<(), String> {
        let (cw, ch) = (canvas.width.max(1) as u32, canvas.height.max(1) as u32);
        let free = |c: &Connection| c.buffers.get(&w.id).map_or(Some(0), |b| (0..2).find(|&i| !b.held[i]));
        let mut index = free(self);
        for _ in 0..100 {
            if index.is_some() {
                break;
            }
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, 10).unwrap_or(0) > 0 {
                self.read()?;
            }
            index = free(self);
        }
        // Strata kept both (it shouldn't): the older one, rather than none.
        let i = index.unwrap_or(0);
        let full = Rect::new(0, 0, cw as i32, ch as i32);
        let b = self.buffers.entry(w.id).or_default();
        let fresh = b.given[i] || b.shm[i].as_ref().is_none_or(|s| s.width != cw || s.height != ch);
        if fresh {
            let shm = Shm::new(cw, ch, self.files)?;
            self.files += 1;
            let r = Request::Buffer { win: w.id, width: cw, height: ch, index: i as u8, flags: 0 };
            net::send_fds(self.fd, &r.encode(), &[shm.fd]).map_err(|e| format!("sending the buffer: {e}"))?;
            let b = self.buffers.entry(w.id).or_default();
            b.shm[i] = Some(shm);
            b.given[i] = false;
            b.stale[i] = full;
        }
        let b = self.buffers.entry(w.id).or_default();
        // What changed since the frame shown last (all of it, if that
        // was another size); nothing changed, nothing to show.
        let last =
            b.shown.filter(|&p| p != i).and_then(|p| b.shm[p].as_ref()).filter(|s| s.width == cw && s.height == ch);
        let new = match last {
            Some(s) => changed(&canvas.pixels, s.map.words(), cw as usize),
            None => Some(full),
        };
        let Some(new) = new else { return Ok(()) };
        if let Some(s) = &mut b.shm[i] {
            copy_rect(s.map.words_mut(), &canvas.pixels, cw as usize, new.union(&b.stale[i]).intersect(&full));
        }
        b.stale[i] = Rect::default();
        b.stale[1 - i] = b.stale[1 - i].union(&new);
        b.held[i] = true;
        b.shown = Some(i);
        let (x, y, width, height) = (new.x as u32, new.y as u32, new.w as u32, new.h as u32);
        self.send(&Request::Damage { win: w.id, x, y, width, height, index: i as u8 })
    }
}

impl Connection {
    /// Give Strata buffer `index` (0 or 1) of `w` from the app's own
    /// shared memory `fd`: `width` x `height` pixels, rows `width` apart;
    /// `opaque` when their fourth byte means nothing. Shown with
    /// [`Connection::show`]; [`Connection::present`] puts a buffer of its
    /// own in its place.
    pub fn give(
        &mut self,
        w: &Window,
        index: u8,
        fd: i32,
        width: u32,
        height: u32,
        opaque: bool,
    ) -> Result<(), String> {
        let i = usize::from(index.min(1));
        let flags = if opaque { strata_proto::buffer::OPAQUE } else { 0 };
        let r = Request::Buffer { win: w.id, width, height, index: i as u8, flags };
        net::send_fds(self.fd, &r.encode(), &[fd]).map_err(|e| format!("sending the buffer: {e}"))?;
        let b = self.buffers.entry(w.id).or_default();
        b.shm[i] = None;
        b.given[i] = true;
        Ok(())
    }

    /// Whether Strata may still be reading buffer `index` of `w`.
    pub fn held(&self, w: &Window, index: u8) -> bool {
        self.buffers.get(&w.id).is_some_and(|b| b.held[usize::from(index.min(1))])
    }

    /// Show buffer `index` of `w`, given with [`Connection::give`]: these
    /// rectangles of it (x, y, width, height) changed since the frame
    /// shown before.
    pub fn show(&mut self, w: &Window, index: u8, rects: &[(u32, u32, u32, u32)]) -> Result<(), String> {
        let i = usize::from(index.min(1));
        let b = self.buffers.entry(w.id).or_default();
        b.held[i] = true;
        b.shown = Some(i);
        // At least one record, which is what shows the buffer.
        let none = [(0, 0, 0, 0)];
        let rects = if rects.is_empty() { &none[..] } else { rects };
        let mut out = Vec::new();
        for &(x, y, width, height) in rects {
            out.extend(Request::Damage { win: w.id, x, y, width, height, index: i as u8 }.encode());
        }
        io::write_all(self.fd, &out).map_err(|e| format!("talking to Strata: {e}"))
    }

    /// How many of `w`'s frames Strata has said are on the screen.
    pub fn frames(&self, w: &Window) -> u64 {
        self.buffers.get(&w.id).map_or(0, |b| b.frames)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

/// A window's shared memory: an unlinked file in a tmpfs, mapped.
#[derive(Debug)]
struct Shm {
    fd: i32,
    map: Mapping,
    width: u32,
    height: u32,
}

impl Shm {
    fn new(width: u32, height: u32, n: u32) -> Result<Shm, String> {
        let len = (width as usize) * (height as usize) * 4;
        let dir = if fs::exists(b"/dev/shm") { "/dev/shm" } else { "/tmp" };
        let path = format!("{dir}/.strata-{}-{n}", process::getpid());
        let fd = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600)
            .map_err(|e| format!("{path}: {e}"))?;
        let _ = fs::unlink(path.as_bytes());
        fs::ftruncate(fd, len as u64).map_err(|e| format!("{path}: {e}"))?;
        let map = Mapping::shared(fd, len, 0).map_err(|e| format!("mapping {path}: {e}"))?;
        Ok(Shm { fd, map, width, height })
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

/// A window: its size in device pixels, scale and focus, as Strata last
/// said.
#[derive(Debug)]
pub struct Window {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub scale: f32,
    pub focused: bool,
}

impl Window {
    /// Take a `Configure` for this window; true if its size changed.
    pub fn configure(&mut self, e: &Event) -> bool {
        match e {
            Event::Configure { win, width, height, scale, focused } if *win == self.id => {
                let resized = (*width, *height) != (self.width, self.height);
                (self.width, self.height) = (*width, *height);
                self.scale = *scale as f32 / 100.0;
                self.focused = *focused;
                resized
            }
            _ => false,
        }
    }

    /// A canvas of the window's size to draw into.
    pub fn canvas(&self, background: slate_ui::Color) -> Canvas {
        Canvas::new(self.width.max(1) as i32, self.height.max(1) as i32, background)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn finds_what_changed() {
        let a = vec![1u32; 40];
        let mut b = a.clone();
        assert_eq!(changed(&a, &b, 8), None);
        b[8 + 3] = 2;
        b[3 * 8 + 1] = 2;
        b[3 * 8 + 5] = 2;
        assert_eq!(changed(&a, &b, 8), Some(Rect::new(1, 1, 5, 3)));
        b[39] = 9;
        assert_eq!(changed(&a, &b, 8), Some(Rect::new(1, 1, 7, 4)));
    }

    #[test]
    fn copies_a_rectangle() {
        let src: Vec<u32> = (0..40).collect();
        let mut dst = vec![0u32; 40];
        copy_rect(&mut dst, &src, 8, Rect::new(2, 1, 3, 2));
        let copied: Vec<usize> = (0..40).filter(|&i| dst[i] != 0).collect();
        assert_eq!(copied, [10, 11, 12, 18, 19, 20]);
        assert!(copied.iter().all(|&i| dst[i] == src[i]));
    }
}
