// SPDX-License-Identifier: MIT OR Apache-2.0

//! `wl-probe` (M31 phase 1): a small Wayland client of Slate's own that
//! the measurements and tests run in a Linux runtime in place of an app,
//! so what they time is the path to Strata and not the app.
//!
//! `wl-probe [--frames N] [--keys N] [--damage full|small] [--size WxH]
//! [--title T]` opens one xdg_toplevel and draws into wl_shm buffers
//! (XRGB8888, two of them, each reused once the compositor releases it):
//! - `--frames N` draws N frames, each when the compositor's frame
//!   callback says the last was shown, all of the window changed or
//!   (`--damage small`) a 32-pixel square moving across it; then it says
//!   how long they took (`wl-probe: N frames in X ms, ...`);
//! - `--keys N` waits for N key presses (wl_keyboard), drawing a new frame
//!   for each, then says so.
//!
//! It says when its first frame was committed, in ms since
//! `SLATE_LINUX_T0` (slate-linux-app sets it), and ends when it is done or
//! its window is closed.
//!
//! Opcodes and argument orders are wayland.xml's and xdg-shell.xml's.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::mem::Mapping;
use slate_rt::{io, lossy};

use crate::conn::{self, Wl, shm_file, socket_path};
use crate::pixels::XRGB8888;
use crate::wire::{Args, Msg, Out};

/// What the probe is asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opts {
    pub frames: u32,
    pub keys: u32,
    pub small: bool,
    pub size: (u32, u32),
    pub title: String,
}

pub fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { frames: 0, keys: 0, small: false, size: (640, 480), title: String::from("wl-probe") };
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let v = args.get(i + 1).ok_or_else(|| format!("{a} needs a value"))?;
        let n = || v.parse::<u32>().map_err(|_| format!("{a}: not a number: {v}"));
        match a.as_str() {
            "--frames" => o.frames = n()?,
            "--keys" => o.keys = n()?,
            "--damage" => {
                o.small = match v.as_str() {
                    "small" => true,
                    "full" => false,
                    _ => return Err(format!("--damage: full or small, not {v}")),
                }
            }
            "--size" => {
                let (w, h) = v.split_once('x').ok_or("--size: WxH")?;
                o.size = (w.parse().map_err(|_| "--size: WxH")?, h.parse().map_err(|_| "--size: WxH")?);
            }
            "--title" => o.title = v.clone(),
            _ => {
                return Err(format!(
                    "unknown option {a}\nusage: wl-probe [--frames N] [--keys N] [--damage full|small] [--size WxH] [--title T]"
                ));
            }
        }
        i += 2;
    }
    Ok(o)
}

/// Frame `n`'s colour (0x00RRGGBB): a different one each frame.
pub fn colour(n: u32) -> u32 {
    let n = n.wrapping_mul(0x9E37_79B9);
    (n >> 8) & 0x00FF_FFFF
}

/// Draw frame `n` into `px` (`w` x `h`), all of it: in its colour, or
/// black with a 32-pixel square in its colour (`small`), 8 pixels on from
/// frame `n - 1`'s along the rows. What changed since frame `n - 1`:
/// (x, y, w, h).
pub fn draw(px: &mut [u32], w: u32, h: u32, n: u32, small: bool) -> (u32, u32, u32, u32) {
    if !small || w < 32 || h < 32 {
        px[..(w * h) as usize].fill(colour(n));
        return (0, 0, w, h);
    }
    let step = (w - 32) / 8 + 1;
    let at = |k: u32| ((k % step) * 8, (k / step * 32) % (h - 31));
    px[..(w * h) as usize].fill(0);
    let (x, y) = at(n);
    for row in y..y + 32 {
        px[(row * w + x) as usize..(row * w + x + 32) as usize].fill(colour(n));
    }
    if n == 0 {
        return (0, 0, w, h);
    }
    let (ox, oy) = at(n - 1);
    let (l, t) = (ox.min(x), oy.min(y));
    let (r, b) = (ox.max(x) + 32, oy.max(y) + 32);
    (l, t, r - l, b - t)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Display,
    Registry,
    Callback,
    FrameCallback,
    Compositor,
    Shm,
    Pool,
    Buffer,
    Surface,
    WmBase,
    XdgSurface,
    Toplevel,
    Seat,
    Keyboard,
}

struct Buf {
    id: u32,
    busy: bool,
}

struct Probe {
    wl: Wl<Kind>,
    o: Opts,
    globals: Vec<(u32, String, u32)>,
    synced: Option<u32>,
    surface: u32,
    xdg_surface: u32,
    configured: Option<u32>,
    /// The first configure was acknowledged: buffers may be attached.
    acked: bool,
    size: (u32, u32),
    want: (u32, u32),
    map: Option<Mapping>,
    pool: u32,
    bufs: Vec<Buf>,
    keyboard: u32,
    /// A frame callback is outstanding.
    waiting: bool,
    drawn: u32,
    keys: u32,
    /// A frame is owed (a key, or the next of `--frames`).
    owed: bool,
    closed: bool,
    first: Option<u64>,
    started: i64,
    shown: Vec<i64>,
}

impl Probe {
    fn bind(&mut self, registry: u32, iface: &str, version: u32, kind: Kind) -> Result<Option<u32>, String> {
        let Some((name, _, v)) = self.globals.iter().find(|g| g.1 == iface).cloned() else { return Ok(None) };
        let id = self.wl.id(kind);
        self.wl.send(Out::new(registry, 0).uint(name).string(iface).uint(v.min(version)).uint(id))?;
        Ok(Some(id))
    }

    fn handle(&mut self, msgs: Vec<Msg>) -> Result<(), String> {
        for m in msgs {
            let mut a = Args::new(&m.body);
            match (self.wl.kinds.get(&m.object).copied(), m.opcode) {
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
                    if let (Some(name), Some(iface), Some(v)) = (a.uint(), a.string(), a.uint()) {
                        self.globals.push((name, iface, v));
                    }
                }
                (Some(Kind::Callback), 0) if self.synced == Some(m.object) => self.synced = None,
                (Some(Kind::FrameCallback), 0) => {
                    self.waiting = false;
                    self.shown.push(conn::now_us());
                    if self.drawn < self.o.frames {
                        self.owed = true;
                    }
                }
                (Some(Kind::Buffer), 0) => {
                    if let Some(b) = self.bufs.iter_mut().find(|b| b.id == m.object) {
                        b.busy = false;
                    }
                }
                // wm_base.ping: pong.
                (Some(Kind::WmBase), 0) => {
                    let serial = a.uint().unwrap_or(0);
                    self.wl.send(Out::new(m.object, 3).uint(serial))?;
                }
                (Some(Kind::XdgSurface), 0) => self.configured = a.uint(),
                (Some(Kind::Toplevel), 0) => {
                    if let (Some(w), Some(h)) = (a.int(), a.int())
                        && w > 0
                        && h > 0
                    {
                        self.want = (w as u32, h as u32);
                    }
                }
                (Some(Kind::Toplevel), 1) => self.closed = true,
                // seat.capabilities: a keyboard (bit 2) when keys are wanted.
                (Some(Kind::Seat), 0) => {
                    if a.uint().unwrap_or(0) & 2 != 0 && self.keyboard == 0 && self.o.keys > 0 {
                        self.keyboard = self.wl.id(Kind::Keyboard);
                        self.wl.send(Out::new(m.object, 1).uint(self.keyboard))?;
                    }
                }
                // keyboard.keymap: its descriptor isn't needed.
                (Some(Kind::Keyboard), 0) => {
                    if let Some(fd) = self.wl.fds.pop_front() {
                        let _ = io::close(fd);
                    }
                }
                // keyboard.key: a press is drawn.
                (Some(Kind::Keyboard), 3) => {
                    let (_serial, _time, key, state) = (a.uint(), a.uint(), a.uint(), a.uint());
                    if state == Some(1) && self.keys < self.o.keys {
                        self.keys += 1;
                        slate_rt::eprintln!("wl-probe: key {} ({})", self.keys, key.unwrap_or(0));
                        self.owed = true;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

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

    /// Buffers of the size wanted (two, in one pool).
    fn buffers(&mut self, shm: u32) -> Result<(), String> {
        if self.size == self.want && self.map.is_some() {
            return Ok(());
        }
        for b in self.bufs.drain(..) {
            self.wl.send(Out::new(b.id, 0))?;
        }
        if self.pool != 0 {
            self.wl.send(Out::new(self.pool, 1))?;
        }
        self.size = self.want;
        let (w, h) = self.size;
        let one = (w * h * 4) as usize;
        let fd = shm_file(one * 2)?;
        self.map = Some(Mapping::shared(fd, one * 2, 0).map_err(|e| format!("mapping the buffers: {e}"))?);
        self.pool = self.wl.id(Kind::Pool);
        self.wl.send_fd(Out::new(shm, 0).uint(self.pool).int((one * 2) as i32), fd)?;
        let _ = io::close(fd);
        for i in 0..2 {
            let id = self.wl.id(Kind::Buffer);
            self.wl.send(
                Out::new(self.pool, 0)
                    .uint(id)
                    .int((i * one) as i32)
                    .int(w as i32)
                    .int(h as i32)
                    .int((w * 4) as i32)
                    .uint(XRGB8888),
            )?;
            self.bufs.push(Buf { id, busy: false });
        }
        Ok(())
    }

    /// Draw and commit the next frame, if a buffer is free.
    fn frame(&mut self, shm: u32) -> Result<(), String> {
        self.buffers(shm)?;
        let Some(i) = self.bufs.iter().position(|b| !b.busy) else { return Ok(()) };
        let (w, h) = self.size;
        let one = (w * h) as usize;
        let n = self.drawn;
        let small = self.o.small;
        let Some(map) = self.map.as_mut() else { return Ok(()) };
        let px = &mut map.words_mut()[i * one..(i + 1) * one];
        let (x, y, dw, dh) = draw(px, w, h, n, small);
        let buf = self.bufs[i].id;
        self.bufs[i].busy = true;
        let cb = self.wl.id(Kind::FrameCallback);
        self.wl.send(Out::new(self.surface, 1).uint(buf).int(0).int(0))?;
        self.wl.send(Out::new(self.surface, 9).int(x as i32).int(y as i32).int(dw as i32).int(dh as i32))?;
        self.wl.send(Out::new(self.surface, 3).uint(cb))?;
        self.wl.send(Out::new(self.surface, 6))?;
        self.waiting = true;
        self.owed = false;
        self.drawn += 1;
        if self.first.is_none() {
            let t0 = conn::t0_ns();
            self.first = Some(conn::since_ms(t0));
            self.started = conn::now_us();
            slate_rt::eprintln!("wl-probe: first frame committed at {} ms", conn::since_ms(t0));
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.closed || (self.drawn >= self.o.frames.max(1) && self.keys >= self.o.keys && !self.waiting)
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    match parse(&args).and_then(run) {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("wl-probe: {e}");
            1
        }
    }
}

fn run(o: Opts) -> Result<(), String> {
    let dir = slate_rt::env::var(b"XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
    let path = socket_path(&dir).ok_or("no compositor's socket")?;
    let wl = Wl::connect(&path, Kind::Display)?;
    let want = o.size;
    let mut p = Probe {
        wl,
        o,
        globals: Vec::new(),
        synced: None,
        surface: 0,
        xdg_surface: 0,
        configured: None,
        acked: false,
        size: (0, 0),
        want,
        map: None,
        pool: 0,
        bufs: Vec::new(),
        keyboard: 0,
        waiting: false,
        drawn: 0,
        keys: 0,
        owed: true,
        closed: false,
        first: None,
        started: 0,
        shown: Vec::new(),
    };
    let registry = p.wl.id(Kind::Registry);
    p.wl.send(Out::new(1, 1).uint(registry))?;
    p.roundtrip()?;
    let need = |r: Option<u32>, what: &str| r.ok_or_else(|| format!("the compositor has no {what}"));
    let compositor = need(p.bind(registry, "wl_compositor", 4, Kind::Compositor)?, "wl_compositor")?;
    let shm = need(p.bind(registry, "wl_shm", 1, Kind::Shm)?, "wl_shm")?;
    let wm = need(p.bind(registry, "xdg_wm_base", 1, Kind::WmBase)?, "xdg_wm_base")?;
    if p.o.keys > 0 {
        need(p.bind(registry, "wl_seat", 5, Kind::Seat)?, "wl_seat")?;
    }
    p.surface = p.wl.id(Kind::Surface);
    p.wl.send(Out::new(compositor, 0).uint(p.surface))?;
    p.xdg_surface = p.wl.id(Kind::XdgSurface);
    p.wl.send(Out::new(wm, 2).uint(p.xdg_surface).uint(p.surface))?;
    let toplevel = p.wl.id(Kind::Toplevel);
    p.wl.send(Out::new(p.xdg_surface, 1).uint(toplevel))?;
    let title = p.o.title.clone();
    p.wl.send(Out::new(toplevel, 2).string(&title))?;
    p.wl.send(Out::new(toplevel, 3).string("wl-probe"))?;
    p.wl.send(Out::new(p.surface, 6))?;
    loop {
        if let Some(serial) = p.configured.take() {
            p.wl.send(Out::new(p.xdg_surface, 4).uint(serial))?;
            p.acked = true;
            // A new size is drawn whole.
            if p.want != p.size && p.size != (0, 0) {
                p.owed = true;
            }
        }
        if p.owed && !p.waiting && p.acked {
            p.frame(shm)?;
        }
        if p.done() {
            break;
        }
        let mut fds = [io::PollFd { fd: p.wl.fd, events: io::POLLIN, revents: 0 }];
        // Keys come when someone types them.
        let secs = if p.keys < p.o.keys { 120 } else { 5 };
        let _ = io::poll(&mut fds, secs * 1000);
        if fds[0].revents == 0 {
            return Err(format!("nothing from the compositor for {secs} s ({} frames, {} keys)", p.drawn, p.keys));
        }
        let msgs = p.wl.read()?;
        p.handle(msgs)?;
    }
    if p.o.frames > 1 {
        let mut gaps: Vec<i64> = p.shown.windows(2).map(|w| w[1] - w[0]).collect();
        let total = p.shown.last().copied().unwrap_or(p.started) - p.started;
        slate_rt::eprintln!(
            "wl-probe: {} frames in {} ms, interval p50 {} us, p95 {} us",
            p.drawn,
            total / 1000,
            conn::percentile(&mut gaps, 50),
            conn::percentile(&mut gaps, 95)
        );
    }
    if p.o.keys > 0 {
        slate_rt::eprintln!("wl-probe: {} keys drawn", p.keys);
    }
    if p.closed {
        slate_rt::eprintln!("wl-probe: closed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn options() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let o = parse(&a(&["--frames", "300", "--damage", "small", "--size", "800x600"])).unwrap();
        assert_eq!((o.frames, o.keys, o.small, o.size), (300, 0, true, (800, 600)));
        assert!(parse(&a(&["--frames"])).is_err());
        assert!(parse(&a(&["--damage", "some"])).is_err());
        assert!(parse(&a(&["--bogus", "1"])).is_err());
    }

    #[test]
    fn frames_differ_and_squares_move() {
        assert_ne!(colour(0), colour(1));
        let (w, h) = (128u32, 64u32);
        let mut px = alloc::vec![0u32; (w * h) as usize];
        assert_eq!(draw(&mut px, w, h, 0, false), (0, 0, w, h));
        assert!(px.iter().all(|&p| p == colour(0)));
        assert_eq!(draw(&mut px, w, h, 0, true), (0, 0, w, h));
        let r = draw(&mut px, w, h, 1, true);
        // From (0, 0) to (8, 0): 40 x 32.
        assert_eq!(r, (0, 0, 40, 32));
        assert_eq!(px[8], colour(1));
        assert_eq!(px[0], 0);
        // Wrapping to the next band.
        let step = (w - 32) / 8 + 1;
        let r = draw(&mut px, w, h, step, true);
        assert_eq!((r.0, r.1), (0, 0));
        assert_eq!(px[(32 * w) as usize], colour(step));
    }
}
